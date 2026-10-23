package dev.chimera.vm;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.AnalyzerException;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.BasicVerifier;
import org.objectweb.asm.tree.analysis.Frame;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Compiles the body of a {@code @ChimeraVM} method into Chimera VM instructions (format v3).
 *
 * <p>Supported: static methods whose parameters and return type are {@code int}, {@code long},
 * {@code double} or a non-array object type; control flow (if/else, for/while, no switch);
 * arithmetic/bitwise/shift/comparison instructions; {@code GETFIELD}/{@code GETSTATIC} for field
 * reads and {@code INVOKESTATIC} as a MethodHandle bridge. Everything else - instance calls,
 * switch, arrays, exceptions, monitors, float - is rejected and the transformer keeps the
 * original Java bytecode. Field/method references are stored as a build-time member table and
 * resolved reflectively at runtime; Minecraft/Fabric references are rejected earlier by
 * {@code FabricSafetyGuard}.</p>
 */
public final class VmCompiler {

    public static final int MAX_CODE_BYTES = 1 << 20;
    private static final int MAX_PC = 0xffff;
    private static final int MAX_PARAMETERS = 64;
    private static final int MAX_ARGUMENTS = 255;

    private VmCompiler() {
    }

    /** kind: 0 = field, 1 = static method. */
    public record Member(int kind, String owner, String name, String desc) {
    }

    public record Compiled(String descriptor, byte[] code, int[] offsets, int maxStack,
                           int maxLocals, List<Member> members) {
    }

    public static Compiled compile(MethodNode method) {
        if (method == null || method.instructions == null) {
            return null;
        }
        if ((method.access & Opcodes.ACC_STATIC) == 0) {
            return null;
        }
        if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE | Opcodes.ACC_SYNCHRONIZED)) != 0) {
            return null;
        }
        if (method.name.startsWith("<")) {
            return null;
        }
        if (method.tryCatchBlocks != null && !method.tryCatchBlocks.isEmpty()) {
            return null;
        }
        Type[] arguments = Type.getArgumentTypes(method.desc);
        Type returnType = Type.getReturnType(method.desc);
        if (!isSupportedType(returnType) || arguments.length > MAX_PARAMETERS) {
            return null;
        }
        for (Type argument : arguments) {
            if (!isSupportedType(argument)) {
                return null;
            }
        }
        if (arguments.length > MAX_ARGUMENTS) {
            return null;
        }

        List<AbstractInsnNode> body = new ArrayList<>();
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            int opcode = insn.getOpcode();
            if (opcode < 0 || opcode == Opcodes.NOP) {
                continue;
            }
            if (!isSupportedOpcode(opcode)) {
                return null;
            }
            body.add(insn);
        }
        if (body.isEmpty() || body.size() > MAX_PC) {
            return null;
        }
        int lastOpcode = body.get(body.size() - 1).getOpcode();
        if (!isReturn(lastOpcode)) {
            return null;
        }

        Frame<BasicValue>[] frames;
        int maxStack;
        int maxLocals;
        try {
            Analyzer<BasicValue> analyzer = new Analyzer<>(new BasicVerifier());
            frames = analyzer.analyze(method.name, method);
            int computedStack = 1;
            int computedLocals = 0;
            for (Frame<BasicValue> frame : frames) {
                if (frame == null) {
                    continue;
                }
                computedStack = Math.max(computedStack, frame.getStackSize());
                computedLocals = Math.max(computedLocals, frame.getLocals());
            }
            maxStack = computedStack;
            maxLocals = Math.max(computedLocals, method.maxLocals);
        } catch (AnalyzerException | RuntimeException e) {
            return null;
        }
        if (maxStack > 0xffff || maxLocals > 0xffff) {
            return null;
        }
        Map<AbstractInsnNode, Integer> insnIndex = new IdentityHashMap<>();
        int index = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            insnIndex.put(insn, Integer.valueOf(index));
            index++;
        }
        for (AbstractInsnNode insn : body) {
            Integer at = insnIndex.get(insn);
            if (at == null || at.intValue() >= frames.length || frames[at.intValue()] == null) {
                return null;
            }
        }

        List<Member> members = new ArrayList<>();
        Map<String, Integer> memberIndices = new LinkedHashMap<>();
        Map<AbstractInsnNode, Integer> memberOf = new IdentityHashMap<>();
        for (AbstractInsnNode insn : body) {
            Member member = memberOf(insn);
            if (member == null) {
                continue;
            }
            String key = member.kind() + "|" + member.owner() + "|" + member.name() + "|" + member.desc();
            Integer existing = memberIndices.get(key);
            if (existing == null) {
                existing = Integer.valueOf(members.size());
                members.add(member);
                memberIndices.put(key, existing);
            }
            memberOf.put(insn, existing);
        }
        if (members.size() > 0xffff) {
            return null;
        }

        Map<AbstractInsnNode, Integer> pcOf = new IdentityHashMap<>();
        Map<LabelNode, Integer> pcOfLabel = new IdentityHashMap<>();
        int pc = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof LabelNode label) {
                pcOfLabel.put(label, Integer.valueOf(pc));
                continue;
            }
            int opcode = insn.getOpcode();
            if (opcode < 0 || opcode == Opcodes.NOP) {
                continue;
            }
            pcOf.put(insn, Integer.valueOf(pc));
            pc++;
        }
        if (pc == 0 || pc > MAX_PC) {
            return null;
        }

        ByteArrayOutputStream buffer = new ByteArrayOutputStream(64);
        DataOutputStream out = new DataOutputStream(buffer);
        List<Integer> offsets = new ArrayList<>(body.size() + 1);
        try {
            for (AbstractInsnNode insn : body) {
                offsets.add(Integer.valueOf(buffer.size()));
                if (!emit(insn, out, pcOfLabel, memberOf, body.size())) {
                    return null;
                }
            }
            offsets.add(Integer.valueOf(buffer.size()));
            out.flush();
        } catch (IOException | RuntimeException e) {
            return null;
        }
        byte[] code = buffer.toByteArray();
        if (code.length == 0 || code.length > MAX_CODE_BYTES) {
            return null;
        }
        int[] offsetsArray = new int[offsets.size()];
        for (int i = 0; i < offsets.size(); i++) {
            offsetsArray[i] = offsets.get(i).intValue();
        }
        if (offsetsArray[0] != 0 || offsetsArray[offsetsArray.length - 1] != code.length) {
            return null;
        }
        for (int i = 0; i + 1 < offsetsArray.length; i++) {
            int length = offsetsArray[i + 1] - offsetsArray[i];
            if (length <= 0 || length > 12) {
                return null;
            }
        }
        return new Compiled(method.desc, code, offsetsArray, maxStack, maxLocals, members);
    }

    /** Returns the member metadata for GETFIELD/GETSTATIC/INVOKESTATIC, or null. */
    private static Member memberOf(AbstractInsnNode insn) {
        if (insn instanceof FieldInsnNode field) {
            int opcode = field.getOpcode();
            if (opcode != Opcodes.GETFIELD && opcode != Opcodes.GETSTATIC
                    && opcode != Opcodes.PUTFIELD && opcode != Opcodes.PUTSTATIC) {
                return null;
            }
            Type type = Type.getType(field.desc);
            if (!isSupportedType(type) || type.getSort() == Type.VOID) {
                return null;
            }
            return new Member(0, field.owner, field.name, field.desc);
        }
        if (insn instanceof MethodInsnNode call) {
            int opcode = call.getOpcode();
            int kind;
            if (opcode == Opcodes.INVOKESTATIC) {
                kind = 1;
            } else if (opcode == Opcodes.INVOKEVIRTUAL) {
                if (call.name.startsWith("<")) {
                    return null; // constructors are not bridged
                }
                kind = 2;
            } else {
                return null;
            }
            Type returnType = Type.getReturnType(call.desc);
            boolean voidReturn = returnType.getSort() == Type.VOID;
            if (!voidReturn && !isSupportedType(returnType)) {
                return null;
            }
            for (Type argument : Type.getArgumentTypes(call.desc)) {
                if (!isSupportedType(argument)) {
                    return null;
                }
            }
            return new Member(kind, call.owner, call.name, call.desc);
        }
        return null;
    }

    private static boolean isSupportedType(Type type) {
        int sort = type.getSort();
        if (sort == Type.INT || sort == Type.LONG || sort == Type.DOUBLE) {
            return true;
        }
        return sort == Type.OBJECT; // arrays are Type.ARRAY and rejected
    }

    private static int kindOf(Type type) {
        return switch (type.getSort()) {
            case Type.INT -> VmOpcode.TYPE_I;
            case Type.LONG -> VmOpcode.TYPE_L;
            case Type.DOUBLE -> VmOpcode.TYPE_D;
            case Type.OBJECT -> VmOpcode.TYPE_O;
            case Type.VOID -> VmOpcode.TYPE_V;
            default -> -1;
        };
    }

    private static boolean isReturn(int opcode) {
        return opcode == Opcodes.IRETURN || opcode == Opcodes.LRETURN
                || opcode == Opcodes.DRETURN || opcode == Opcodes.ARETURN;
    }

    private static boolean isSupportedOpcode(int opcode) {
        switch (opcode) {
            case Opcodes.ICONST_M1:
            case Opcodes.ICONST_0:
            case Opcodes.ICONST_1:
            case Opcodes.ICONST_2:
            case Opcodes.ICONST_3:
            case Opcodes.ICONST_4:
            case Opcodes.ICONST_5:
            case Opcodes.BIPUSH:
            case Opcodes.SIPUSH:
            case Opcodes.LDC:
            case Opcodes.LCONST_0:
            case Opcodes.LCONST_1:
            case Opcodes.DCONST_0:
            case Opcodes.DCONST_1:
            case Opcodes.ILOAD:
            case Opcodes.LLOAD:
            case Opcodes.DLOAD:
            case Opcodes.ALOAD:
            case Opcodes.ISTORE:
            case Opcodes.LSTORE:
            case Opcodes.DSTORE:
            case Opcodes.ASTORE:
            case Opcodes.IINC:
            case Opcodes.IADD:
            case Opcodes.ISUB:
            case Opcodes.IMUL:
            case Opcodes.IDIV:
            case Opcodes.IREM:
            case Opcodes.INEG:
            case Opcodes.IAND:
            case Opcodes.IOR:
            case Opcodes.IXOR:
            case Opcodes.ISHL:
            case Opcodes.ISHR:
            case Opcodes.IUSHR:
            case Opcodes.I2B:
            case Opcodes.I2C:
            case Opcodes.I2S:
            case Opcodes.LADD:
            case Opcodes.LSUB:
            case Opcodes.LMUL:
            case Opcodes.LDIV:
            case Opcodes.LREM:
            case Opcodes.LNEG:
            case Opcodes.LAND:
            case Opcodes.LOR:
            case Opcodes.LXOR:
            case Opcodes.LSHL:
            case Opcodes.LSHR:
            case Opcodes.LUSHR:
            case Opcodes.LCMP:
            case Opcodes.DADD:
            case Opcodes.DSUB:
            case Opcodes.DMUL:
            case Opcodes.DDIV:
            case Opcodes.DREM:
            case Opcodes.DNEG:
            case Opcodes.DCMPG:
            case Opcodes.DCMPL:
            case Opcodes.I2L:
            case Opcodes.I2D:
            case Opcodes.L2I:
            case Opcodes.L2D:
            case Opcodes.D2I:
            case Opcodes.D2L:
            case Opcodes.GETFIELD:
            case Opcodes.GETSTATIC:
            case Opcodes.PUTFIELD:
            case Opcodes.PUTSTATIC:
            case Opcodes.INVOKESTATIC:
            case Opcodes.INVOKEVIRTUAL:
            case Opcodes.GOTO:
            case Opcodes.IFEQ:
            case Opcodes.IFNE:
            case Opcodes.IFLT:
            case Opcodes.IFGE:
            case Opcodes.IFGT:
            case Opcodes.IFLE:
            case Opcodes.IF_ICMPEQ:
            case Opcodes.IF_ICMPNE:
            case Opcodes.IF_ICMPLT:
            case Opcodes.IF_ICMPGE:
            case Opcodes.IF_ICMPGT:
            case Opcodes.IF_ICMPLE:
            case Opcodes.IRETURN:
            case Opcodes.LRETURN:
            case Opcodes.DRETURN:
            case Opcodes.ARETURN:
                return true;
            default:
                return false;
        }
    }

    private static int mapOpcode(int jvmOpcode) {
        switch (jvmOpcode) {
            case Opcodes.IADD: return VmOpcode.IADD;
            case Opcodes.ISUB: return VmOpcode.ISUB;
            case Opcodes.IMUL: return VmOpcode.IMUL;
            case Opcodes.IDIV: return VmOpcode.IDIV;
            case Opcodes.IREM: return VmOpcode.IREM;
            case Opcodes.INEG: return VmOpcode.INEG;
            case Opcodes.IAND: return VmOpcode.IAND;
            case Opcodes.IOR: return VmOpcode.IOR;
            case Opcodes.IXOR: return VmOpcode.IXOR;
            case Opcodes.ISHL: return VmOpcode.ISHL;
            case Opcodes.ISHR: return VmOpcode.ISHR;
            case Opcodes.IUSHR: return VmOpcode.IUSHR;
            case Opcodes.I2B: return VmOpcode.I2B;
            case Opcodes.I2C: return VmOpcode.I2C;
            case Opcodes.I2S: return VmOpcode.I2S;
            case Opcodes.LADD: return VmOpcode.LADD;
            case Opcodes.LSUB: return VmOpcode.LSUB;
            case Opcodes.LMUL: return VmOpcode.LMUL;
            case Opcodes.LDIV: return VmOpcode.LDIV;
            case Opcodes.LREM: return VmOpcode.LREM;
            case Opcodes.LNEG: return VmOpcode.LNEG;
            case Opcodes.LAND: return VmOpcode.LAND;
            case Opcodes.LOR: return VmOpcode.LOR;
            case Opcodes.LXOR: return VmOpcode.LXOR;
            case Opcodes.LSHL: return VmOpcode.LSHL;
            case Opcodes.LSHR: return VmOpcode.LSHR;
            case Opcodes.LUSHR: return VmOpcode.LUSHR;
            case Opcodes.LCMP: return VmOpcode.LCMP;
            case Opcodes.DADD: return VmOpcode.DADD;
            case Opcodes.DSUB: return VmOpcode.DSUB;
            case Opcodes.DMUL: return VmOpcode.DMUL;
            case Opcodes.DDIV: return VmOpcode.DDIV;
            case Opcodes.DREM: return VmOpcode.DREM;
            case Opcodes.DNEG: return VmOpcode.DNEG;
            case Opcodes.DCMPG: return VmOpcode.DCMPG;
            case Opcodes.DCMPL: return VmOpcode.DCMPL;
            case Opcodes.I2L: return VmOpcode.I2L;
            case Opcodes.I2D: return VmOpcode.I2D;
            case Opcodes.L2I: return VmOpcode.L2I;
            case Opcodes.L2D: return VmOpcode.L2D;
            case Opcodes.D2I: return VmOpcode.D2I;
            case Opcodes.D2L: return VmOpcode.D2L;
            default: return -1;
        }
    }

    private static boolean emit(AbstractInsnNode insn, DataOutputStream out,
                                Map<LabelNode, Integer> pcOfLabel,
                                Map<AbstractInsnNode, Integer> memberOf, int instructionCount)
            throws IOException {
        int opcode = insn.getOpcode();
        if (insn instanceof FieldInsnNode) {
            Integer member = memberOf.get(insn);
            if (member == null) {
                return false;
            }
            Type type = Type.getType(expectedFieldDesc(insn));
            int kind = kindOf(type);
            if (kind < 0) {
                return false;
            }
            int vmOpcode;
            switch (opcode) {
                case Opcodes.GETFIELD: vmOpcode = VmOpcode.GETFIELD; break;
                case Opcodes.GETSTATIC: vmOpcode = VmOpcode.GETSTATIC; break;
                case Opcodes.PUTFIELD: vmOpcode = VmOpcode.PUTFIELD; break;
                case Opcodes.PUTSTATIC: vmOpcode = VmOpcode.PUTSTATIC; break;
                default: return false;
            }
            out.writeByte(vmOpcode);
            out.writeShort(member.intValue());
            out.writeByte(kind);
            return true;
        }
        if (insn instanceof MethodInsnNode) {
            Integer member = memberOf.get(insn);
            if (member == null) {
                return false;
            }
            Type[] arguments = Type.getArgumentTypes(((MethodInsnNode) insn).desc);
            int returnKind = kindOf(Type.getReturnType(((MethodInsnNode) insn).desc));
            if (returnKind < 0) {
                return false;
            }
            out.writeByte(opcode == Opcodes.INVOKEVIRTUAL
                    ? VmOpcode.INVOKEVIRTUAL : VmOpcode.INVOKESTATIC);
            out.writeShort(member.intValue());
            out.writeByte(arguments.length);
            out.writeByte(returnKind);
            return true;
        }
        if (insn instanceof InsnNode) {
            switch (opcode) {
                case Opcodes.ICONST_M1:
                case Opcodes.ICONST_0:
                case Opcodes.ICONST_1:
                case Opcodes.ICONST_2:
                case Opcodes.ICONST_3:
                case Opcodes.ICONST_4:
                case Opcodes.ICONST_5:
                    out.writeByte(VmOpcode.PUSH_I);
                    out.writeInt(opcode - Opcodes.ICONST_0);
                    return true;
                case Opcodes.LCONST_0:
                case Opcodes.LCONST_1:
                    out.writeByte(VmOpcode.PUSH_L);
                    out.writeLong(opcode - Opcodes.LCONST_0);
                    return true;
                case Opcodes.DCONST_0:
                case Opcodes.DCONST_1:
                    out.writeByte(VmOpcode.PUSH_D);
                    out.writeLong(Double.doubleToRawLongBits(opcode - Opcodes.DCONST_0));
                    return true;
                case Opcodes.IRETURN:
                    out.writeByte(VmOpcode.RET);
                    out.writeByte(VmOpcode.TYPE_I);
                    return true;
                case Opcodes.LRETURN:
                    out.writeByte(VmOpcode.RET);
                    out.writeByte(VmOpcode.TYPE_L);
                    return true;
                case Opcodes.DRETURN:
                    out.writeByte(VmOpcode.RET);
                    out.writeByte(VmOpcode.TYPE_D);
                    return true;
                case Opcodes.ARETURN:
                    out.writeByte(VmOpcode.RET);
                    out.writeByte(VmOpcode.TYPE_O);
                    return true;
                default: {
                    int mapped = mapOpcode(opcode);
                    if (mapped < 0) {
                        return false;
                    }
                    out.writeByte(mapped);
                    return true;
                }
            }
        }
        if (insn instanceof IntInsnNode integer) {
            if (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH) {
                out.writeByte(VmOpcode.PUSH_I);
                out.writeInt(integer.operand);
                return true;
            }
            return false;
        }
        if (insn instanceof LdcInsnNode ldc) {
            Object constant = ldc.cst;
            if (constant instanceof Integer value) {
                out.writeByte(VmOpcode.PUSH_I);
                out.writeInt(value.intValue());
                return true;
            }
            if (constant instanceof Long value) {
                out.writeByte(VmOpcode.PUSH_L);
                out.writeLong(value.longValue());
                return true;
            }
            if (constant instanceof Double value) {
                out.writeByte(VmOpcode.PUSH_D);
                out.writeLong(Double.doubleToRawLongBits(value.doubleValue()));
                return true;
            }
            return false;
        }
        if (insn instanceof VarInsnNode variable) {
            int slot = variable.var;
            if (slot < 0 || slot > 0xffff) {
                return false;
            }
            int type;
            switch (opcode) {
                case Opcodes.ILOAD:
                case Opcodes.ISTORE:
                    type = VmOpcode.TYPE_I;
                    break;
                case Opcodes.LLOAD:
                case Opcodes.LSTORE:
                    type = VmOpcode.TYPE_L;
                    break;
                case Opcodes.DLOAD:
                case Opcodes.DSTORE:
                    type = VmOpcode.TYPE_D;
                    break;
                case Opcodes.ALOAD:
                case Opcodes.ASTORE:
                    type = VmOpcode.TYPE_O;
                    break;
                default:
                    return false;
            }
            boolean load = opcode == Opcodes.ILOAD || opcode == Opcodes.LLOAD
                    || opcode == Opcodes.DLOAD || opcode == Opcodes.ALOAD;
            out.writeByte(load ? VmOpcode.LOAD : VmOpcode.STORE);
            out.writeByte(type);
            out.writeShort(slot);
            return true;
        }
        if (insn instanceof IincInsnNode increment) {
            int slot = increment.var;
            int delta = increment.incr;
            if (slot < 0 || slot > 0xffff || delta < Byte.MIN_VALUE || delta > Byte.MAX_VALUE) {
                return false;
            }
            out.writeByte(VmOpcode.IINC);
            out.writeShort(slot);
            out.writeByte(delta);
            return true;
        }
        if (insn instanceof JumpInsnNode jump) {
            Integer target = pcOfLabel.get(jump.label);
            if (target == null || target.intValue() < 0 || target.intValue() >= instructionCount) {
                return false;
            }
            int op;
            switch (opcode) {
                case Opcodes.GOTO: op = VmOpcode.GOTO; break;
                case Opcodes.IFEQ: op = VmOpcode.IFEQ; break;
                case Opcodes.IFNE: op = VmOpcode.IFNE; break;
                case Opcodes.IFLT: op = VmOpcode.IFLT; break;
                case Opcodes.IFGE: op = VmOpcode.IFGE; break;
                case Opcodes.IFGT: op = VmOpcode.IFGT; break;
                case Opcodes.IFLE: op = VmOpcode.IFLE; break;
                case Opcodes.IF_ICMPEQ: op = VmOpcode.IF_ICMPEQ; break;
                case Opcodes.IF_ICMPNE: op = VmOpcode.IF_ICMPNE; break;
                case Opcodes.IF_ICMPLT: op = VmOpcode.IF_ICMPLT; break;
                case Opcodes.IF_ICMPGE: op = VmOpcode.IF_ICMPGE; break;
                case Opcodes.IF_ICMPGT: op = VmOpcode.IF_ICMPGT; break;
                case Opcodes.IF_ICMPLE: op = VmOpcode.IF_ICMPLE; break;
                default: return false;
            }
            out.writeByte(op);
            out.writeShort(target.intValue());
            return true;
        }
        return false;
    }

    private static String expectedFieldDesc(AbstractInsnNode insn) {
        return ((FieldInsnNode) insn).desc;
    }
}
