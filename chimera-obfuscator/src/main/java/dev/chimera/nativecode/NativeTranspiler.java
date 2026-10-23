package dev.chimera.nativecode;

import dev.chimera.core.NativeTemplateWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.AnalyzerException;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.BasicVerifier;
import org.objectweb.asm.tree.analysis.Frame;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Translates a static int/long/double JVM method - including branches, loops and bit arithmetic -
 * into compilable JNI C++.
 *
 * <p>Control flow is recovered with ASM {@link Analyzer} + {@link BasicVerifier}; the generated
 * function pre-declares one variable per JVM local slot / operand-stack slot and per value type
 * ({@code s0_i}, {@code s0_l}, {@code s0_d}), then emits one assignment / if / goto / label per
 * bytecode instruction. Because each static program point reads the slot variables chosen for its
 * verified type, branch merges are naturally consistent.</p>
 *
 * <p>Rejected (TODO stub, never wrong code): try/catch, unreachable code, void/float/object/
 * arrays, fields, calls, switch, monitors, dup family and any opcode outside the documented
 * subset.</p>
 */
public final class NativeTranspiler {
    private NativeTranspiler() {
    }

    /** Result of translating one method: header is always present; body only when supported. */
    public record TranspileResult(boolean supported, String cppBody, String headerDecl) {
    }

    public static TranspileResult transpile(ClassNode owner, MethodNode method) {
        String header = NativeTemplateWriter.headerDeclaration(
                owner.name, method.name, method.desc,
                (method.access & Opcodes.ACC_STATIC) != 0, isOverloaded(owner, method));
        if ((method.access & Opcodes.ACC_STATIC) == 0
                || (method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
            return unsupported(header);
        }
        if (method.tryCatchBlocks != null && !method.tryCatchBlocks.isEmpty()) {
            return unsupported(header);
        }
        if (method.instructions == null || method.instructions.size() == 0) {
            return unsupported(header);
        }
        if (!isSupportedType(Type.getReturnType(method.desc))) {
            return unsupported(header);
        }
        for (Type arg : Type.getArgumentTypes(method.desc)) {
            if (!isSupportedType(arg)) return unsupported(header);
        }
        Frame<BasicValue>[] frames;
        try {
            frames = new Analyzer<>(new BasicVerifier()).analyze(owner.name, method);
        } catch (AnalyzerException | RuntimeException e) {
            return unsupported(header);
        }
        return new Builder(method, frames).build(header);
    }

    /** True when the owner class declares more than one method with this name. */
    private static boolean isOverloaded(ClassNode owner, MethodNode method) {
        if (owner == null || owner.methods == null || method == null) {
            return false;
        }
        int count = 0;
        for (MethodNode candidate : owner.methods) {
            if (candidate.name.equals(method.name)) {
                count++;
            }
        }
        return count > 1;
    }

    private static TranspileResult unsupported(String header) {
        return new TranspileResult(false, null, header);
    }

    private static boolean isSupportedType(Type type) {
        int sort = type.getSort();
        return sort == Type.INT || sort == Type.LONG || sort == Type.DOUBLE;
    }

    private static final class Builder {
        private final MethodNode method;
        private final Frame<BasicValue>[] frames;
        private final AbstractInsnNode[] insns;
        private final Map<LabelNode, Integer> labelIndex = new HashMap<>();
        private final Map<String, String> localInits = new HashMap<>();
        private final Set<String> usedLocals = new LinkedHashSet<>();
        private final Set<String> usedStack = new LinkedHashSet<>();
        private String currentCallDesc;
        private final List<String> statements = new ArrayList<>();

        Builder(MethodNode method, Frame<BasicValue>[] frames) {
            this.method = method;
            this.frames = frames;
            this.insns = method.instructions.toArray();
        }

        TranspileResult build(String header) {
            for (int i = 0; i < insns.length; i++) {
                if (insns[i] instanceof LabelNode label) labelIndex.put(label, i);
            }
            int slot = 0;
            Type[] args = Type.getArgumentTypes(method.desc);
            for (int i = 0; i < args.length; i++) {
                Type arg = args[i];
                localInits.put(localKey(slot, arg.getSort()), "a" + i);
                slot += arg.getSize();
            }
            for (int i = 0; i < insns.length; i++) {
                AbstractInsnNode insn = insns[i];
                if (insn instanceof LabelNode) {
                    statements.add("L" + i + ": ;");
                    continue;
                }
                if (insn instanceof LineNumberNode || insn instanceof FrameNode) continue;
                Frame<BasicValue> frame = frames[i];
                if (frame == null) {
                    // Unreachable bytecode is rejected on purpose: it cannot be reasoned about.
                    return unsupported(header);
                }
                if (!emit(insn, frame, i)) return unsupported(header);
            }
            StringBuilder body = new StringBuilder();
            boolean first = true;
            for (String key : usedLocals) {
                String init = localInits.get(key);
                body.append("    ").append(cppType(sortOfKey(key))).append(' ').append(varName(key))
                    .append(init != null ? " = " + init : "").append(";\n");
                first = false;
            }
            for (String key : usedStack) {
                int colon = key.indexOf(':');
                int depth = Integer.parseInt(key.substring(0, colon));
                int sort = Integer.parseInt(key.substring(colon + 1));
                body.append("    ").append(cppType(sort)).append(" s").append(depth)
                    .append('_').append(letter(sort)).append(";\n");
                first = false;
            }
            if (!first) body.append('\n');
            for (String stmt : statements) body.append("    ").append(stmt).append('\n');
            return new TranspileResult(true, body.toString(), header);
        }

        private boolean emit(AbstractInsnNode insn, Frame<BasicValue> frame, int index) {
            int depth = frame.getStackSize();
            if (insn instanceof InsnNode simple) return emitSimple(simple.getOpcode(), frame, depth);
            if (insn instanceof IntInsnNode intInsn) {
                if (intInsn.getOpcode() != Opcodes.BIPUSH && intInsn.getOpcode() != Opcodes.SIPUSH) return false;
                assign(depth, Type.INT, intLiteral(intInsn.operand));
                return true;
            }
            if (insn instanceof LdcInsnNode ldc) return emitLdc(ldc.cst, depth);
            if (insn instanceof VarInsnNode var) return emitVar(var.getOpcode(), var.var, frame, depth);
            if (insn instanceof IincInsnNode inc) return emitIinc(inc.var, inc.incr, frame);
            if (insn instanceof MethodInsnNode call) return emitMethodCall(call, frame, depth);
            if (insn instanceof JumpInsnNode jump) return emitJump(jump, frame, depth);
            return false;
        }

        private boolean emitSimple(int op, Frame<BasicValue> frame, int depth) {
            if (op >= Opcodes.ICONST_M1 && op <= Opcodes.ICONST_5) {
                assign(depth, Type.INT, Integer.toString(op - Opcodes.ICONST_0));
                return true;
            }
            if (op == Opcodes.LCONST_0 || op == Opcodes.LCONST_1) {
                assign(depth, Type.LONG, (op - Opcodes.LCONST_0) + "L");
                return true;
            }
            if (op == Opcodes.DCONST_0 || op == Opcodes.DCONST_1) {
                assign(depth, Type.DOUBLE, (op - Opcodes.DCONST_0) + ".0");
                return true;
            }
            return switch (op) {
                case Opcodes.NOP -> true;
                case Opcodes.IADD -> intBinary(frame, depth, "+");
                case Opcodes.ISUB -> intBinary(frame, depth, "-");
                case Opcodes.IMUL -> intBinary(frame, depth, "*");
                case Opcodes.IAND -> intBinary(frame, depth, "&");
                case Opcodes.IOR -> intBinary(frame, depth, "|");
                case Opcodes.IXOR -> intBinary(frame, depth, "^");
                case Opcodes.IDIV -> guardedIntBinary(frame, depth, "chimera_idiv");
                case Opcodes.IREM -> guardedIntBinary(frame, depth, "chimera_irem");
                case Opcodes.LADD -> longBinary(frame, depth, "+");
                case Opcodes.LSUB -> longBinary(frame, depth, "-");
                case Opcodes.LMUL -> longBinary(frame, depth, "*");
                case Opcodes.LAND -> longBinary(frame, depth, "&");
                case Opcodes.LOR -> longBinary(frame, depth, "|");
                case Opcodes.LXOR -> longBinary(frame, depth, "^");
                case Opcodes.LDIV -> guardedLongBinary(frame, depth, "chimera_ldiv");
                case Opcodes.LREM -> guardedLongBinary(frame, depth, "chimera_lrem");
                case Opcodes.DADD -> doubleBinary(frame, depth, "+");
                case Opcodes.DSUB -> doubleBinary(frame, depth, "-");
                case Opcodes.DMUL -> doubleBinary(frame, depth, "*");
                case Opcodes.DDIV -> doubleBinary(frame, depth, "/");
                case Opcodes.DREM -> doubleRemainder(frame, depth);
                case Opcodes.INEG -> intNegate(frame, depth);
                case Opcodes.LNEG -> longNegate(frame, depth);
                case Opcodes.DNEG -> doubleNegate(frame, depth);
                case Opcodes.ISHL -> intShift(frame, depth, "shl");
                case Opcodes.ISHR -> intShift(frame, depth, "shr");
                case Opcodes.IUSHR -> intShift(frame, depth, "ushr");
                case Opcodes.LSHL -> longShift(frame, depth, "shl");
                case Opcodes.LSHR -> longShift(frame, depth, "shr");
                case Opcodes.LUSHR -> longShift(frame, depth, "ushr");
                case Opcodes.I2L -> widen(frame, depth, Type.INT, Type.LONG, "(jlong)");
                case Opcodes.I2D -> widen(frame, depth, Type.INT, Type.DOUBLE, "(jdouble)");
                case Opcodes.L2I -> narrowCast(frame, depth, Type.LONG, Type.INT, "(jint)");
                case Opcodes.L2D -> widen(frame, depth, Type.LONG, Type.DOUBLE, "(jdouble)");
                case Opcodes.D2I -> narrowingHelper(frame, depth, Type.DOUBLE, Type.INT, "chimera_d2i");
                case Opcodes.D2L -> narrowingHelper(frame, depth, Type.DOUBLE, Type.LONG, "chimera_d2l");
                case Opcodes.I2B -> intNarrow(frame, depth, "(jbyte)");
                case Opcodes.I2C -> intNarrow(frame, depth, "(jchar)");
                case Opcodes.I2S -> intNarrow(frame, depth, "(jshort)");
                case Opcodes.LCMP -> longCompare(frame, depth);
                case Opcodes.DCMPL -> doubleCompare(frame, depth, "chimera_dcmpl");
                case Opcodes.DCMPG -> doubleCompare(frame, depth, "chimera_dcmpg");
                case Opcodes.IRETURN -> returnValue(frame, depth, Type.INT);
                case Opcodes.LRETURN -> returnValue(frame, depth, Type.LONG);
                case Opcodes.DRETURN -> returnValue(frame, depth, Type.DOUBLE);
                default -> false;
            };
        }

        private boolean emitLdc(Object constant, int depth) {
            if (constant instanceof Integer value) {
                assign(depth, Type.INT, intLiteral(value));
                return true;
            }
            if (constant instanceof Long value) {
                assign(depth, Type.LONG, longLiteral(value));
                return true;
            }
            if (constant instanceof Double value) {
                if (!Double.isFinite(value)) return false;
                assign(depth, Type.DOUBLE, Double.toString(value));
                return true;
            }
            return false;
        }

        private boolean emitVar(int op, int slot, Frame<BasicValue> frame, int depth) {
            return switch (op) {
                case Opcodes.ILOAD -> load(slot, Type.INT, frame, depth);
                case Opcodes.LLOAD -> load(slot, Type.LONG, frame, depth);
                case Opcodes.DLOAD -> load(slot, Type.DOUBLE, frame, depth);
                case Opcodes.ISTORE -> store(slot, Type.INT, depth);
                case Opcodes.LSTORE -> store(slot, Type.LONG, depth);
                case Opcodes.DSTORE -> store(slot, Type.DOUBLE, depth);
                default -> false;
            };
        }

        private boolean emitIinc(int slot, int increment, Frame<BasicValue> frame) {
            if (sortOf(frame.getLocal(slot)) != Type.INT) return false;
            String local = localVar(slot, Type.INT);
            statements.add(local + " = (jint)((chimera_u32)" + local
                    + " + (chimera_u32)" + intLiteral(increment) + ");");
            return true;
        }

        private boolean emitJump(JumpInsnNode jump, Frame<BasicValue> frame, int depth) {
            Integer target = labelIndex.get(jump.label);
            if (target == null) return false;
            String label = "L" + target;
            int op = jump.getOpcode();
            if (op == Opcodes.GOTO) {
                statements.add("goto " + label + ";");
                return true;
            }
            if (op == Opcodes.IFEQ || op == Opcodes.IFNE || op == Opcodes.IFLT
                    || op == Opcodes.IFGE || op == Opcodes.IFGT || op == Opcodes.IFLE) {
                if (depth < 1 || sortOf(frame.getStack(depth - 1)) != Type.INT) return false;
                String value = stackVar(depth - 1, Type.INT);
                String condition = switch (op) {
                    case Opcodes.IFEQ -> value + " == 0";
                    case Opcodes.IFNE -> value + " != 0";
                    case Opcodes.IFLT -> value + " < 0";
                    case Opcodes.IFGE -> value + " >= 0";
                    case Opcodes.IFGT -> value + " > 0";
                    default -> value + " <= 0";
                };
                statements.add("if (" + condition + ") goto " + label + ";");
                return true;
            }
            if (op >= Opcodes.IF_ICMPEQ && op <= Opcodes.IF_ICMPLE) {
                if (depth < 2 || sortOf(frame.getStack(depth - 2)) != Type.INT
                        || sortOf(frame.getStack(depth - 1)) != Type.INT) {
                    return false;
                }
                String left = stackVar(depth - 2, Type.INT);
                String right = stackVar(depth - 1, Type.INT);
                String comparator = switch (op) {
                    case Opcodes.IF_ICMPEQ -> "==";
                    case Opcodes.IF_ICMPNE -> "!=";
                    case Opcodes.IF_ICMPLT -> "<";
                    case Opcodes.IF_ICMPGE -> ">=";
                    case Opcodes.IF_ICMPGT -> ">";
                    default -> "<=";
                };
                statements.add("if (" + left + " " + comparator + " " + right + ") goto " + label + ";");
                return true;
            }
            return false;
        }

        private boolean load(int slot, int sort, Frame<BasicValue> frame, int depth) {
            if (sortOf(frame.getLocal(slot)) != sort) return false;
            statements.add(stackVar(depth, sort) + " = " + localVar(slot, sort) + ";");
            return true;
        }

        private boolean store(int slot, int sort, int depth) {
            if (depth < 1) return false;
            statements.add(localVar(slot, sort) + " = " + stackVar(depth - 1, sort) + ";");
            return true;
        }

        private boolean intBinary(Frame<BasicValue> frame, int depth, String op) {
            if (!stackIs(frame, depth - 2, Type.INT) || !stackIs(frame, depth - 1, Type.INT)) return false;
            String a = stackVar(depth - 2, Type.INT);
            String b = stackVar(depth - 1, Type.INT);
            statements.add(a + " = (jint)((chimera_u32)" + a + " " + op + " (chimera_u32)" + b + ");");
            return true;
        }

        private boolean guardedIntBinary(Frame<BasicValue> frame, int depth, String helper) {
            if (!stackIs(frame, depth - 2, Type.INT) || !stackIs(frame, depth - 1, Type.INT)) return false;
            String a = stackVar(depth - 2, Type.INT);
            String b = stackVar(depth - 1, Type.INT);
            statements.add(a + " = " + helper + "(" + a + ", " + b + ");");
            return true;
        }

        private boolean longBinary(Frame<BasicValue> frame, int depth, String op) {
            if (!stackIs(frame, depth - 2, Type.LONG) || !stackIs(frame, depth - 1, Type.LONG)) return false;
            String a = stackVar(depth - 2, Type.LONG);
            String b = stackVar(depth - 1, Type.LONG);
            statements.add(a + " = (jlong)((chimera_u64)" + a + " " + op + " (chimera_u64)" + b + ");");
            return true;
        }

        private boolean guardedLongBinary(Frame<BasicValue> frame, int depth, String helper) {
            if (!stackIs(frame, depth - 2, Type.LONG) || !stackIs(frame, depth - 1, Type.LONG)) return false;
            String a = stackVar(depth - 2, Type.LONG);
            String b = stackVar(depth - 1, Type.LONG);
            statements.add(a + " = " + helper + "(" + a + ", " + b + ");");
            return true;
        }

        private boolean doubleBinary(Frame<BasicValue> frame, int depth, String op) {
            if (!stackIs(frame, depth - 2, Type.DOUBLE) || !stackIs(frame, depth - 1, Type.DOUBLE)) return false;
            String a = stackVar(depth - 2, Type.DOUBLE);
            String b = stackVar(depth - 1, Type.DOUBLE);
            statements.add(a + " = " + a + " " + op + " " + b + ";");
            return true;
        }

        private boolean doubleRemainder(Frame<BasicValue> frame, int depth) {
            if (!stackIs(frame, depth - 2, Type.DOUBLE) || !stackIs(frame, depth - 1, Type.DOUBLE)) return false;
            String a = stackVar(depth - 2, Type.DOUBLE);
            String b = stackVar(depth - 1, Type.DOUBLE);
            statements.add(a + " = std::fmod(" + a + ", " + b + ");");
            return true;
        }

        private boolean intNegate(Frame<BasicValue> frame, int depth) {
            if (!stackIs(frame, depth - 1, Type.INT)) return false;
            String a = stackVar(depth - 1, Type.INT);
            statements.add(a + " = (jint)((chimera_u32)0 - (chimera_u32)" + a + ");");
            return true;
        }

        private boolean longNegate(Frame<BasicValue> frame, int depth) {
            if (!stackIs(frame, depth - 1, Type.LONG)) return false;
            String a = stackVar(depth - 1, Type.LONG);
            statements.add(a + " = (jlong)((chimera_u64)0 - (chimera_u64)" + a + ");");
            return true;
        }

        /**
         * Pure {@code java.lang.Math}/{@code StrictMath} calls (int/long/double overloads).
         * Field/method calls on other owners are still rejected, so this does not open the
         * transpiler to arbitrary Java method invocation.
         */
        private boolean emitMethodCall(MethodInsnNode call, Frame<BasicValue> frame, int depth) {
            if (call.getOpcode() != Opcodes.INVOKESTATIC) return false;
            if (!call.owner.equals("java/lang/Math") && !call.owner.equals("java/lang/StrictMath")) {
                return false;
            }
            Type[] args = Type.getArgumentTypes(call.desc);
            Type ret = Type.getReturnType(call.desc);
            if (args.length == 0 || ret.getSort() == Type.VOID) return false;
            int base = depth - args.length;
            if (base < 0) return false;
            for (int i = 0; i < args.length; i++) {
                if (!stackIs(frame, base + i, args[i].getSort())) return false;
            }
            currentCallDesc = call.desc;
            String expr = mathExpression(call.name, call.desc, base);
            if (expr == null) return false;
            statements.add(stackVar(base, ret.getSort()) + " = " + expr + ";");
            return true;
        }

        private String arg(int base, int index) {
            Type[] args = Type.getArgumentTypes(currentCallDesc);
            return stackVar(base + index, args[index].getSort());
        }

        private String mathExpression(String name, String desc, int base) {
            String a = stackVar(base, Type.getArgumentTypes(desc)[0].getSort());
            switch (name + desc) {
                case "abs(I)I":
                    return "(jint)(" + a + " < 0 ? (jint)(0u - (chimera_u32)" + a + ") : " + a + ")";
                case "abs(J)J":
                    return "(jlong)(" + a + " < 0 ? (jlong)(0ull - (chimera_u64)" + a + ") : " + a + ")";
                case "abs(D)D":
                    return "std::fabs(" + a + ")";
                case "max(II)I":
                case "max(JJ)J":
                    return "(" + arg(base, 0) + " > " + arg(base, 1) + " ? " + arg(base, 0) + " : " + arg(base, 1) + ")";
                case "min(II)I":
                case "min(JJ)J":
                    return "(" + arg(base, 0) + " < " + arg(base, 1) + " ? " + arg(base, 0) + " : " + arg(base, 1) + ")";
                case "max(DD)D":
                    return "std::fmax(" + arg(base, 0) + ", " + arg(base, 1) + ")";
                case "min(DD)D":
                    return "std::fmin(" + arg(base, 0) + ", " + arg(base, 1) + ")";
                case "sqrt(D)D": return "std::sqrt(" + a + ")";
                case "cbrt(D)D": return "std::cbrt(" + a + ")";
                case "floor(D)D": return "std::floor(" + a + ")";
                case "ceil(D)D": return "std::ceil(" + a + ")";
                case "rint(D)D": return "std::rint(" + a + ")";
                case "sin(D)D": return "std::sin(" + a + ")";
                case "cos(D)D": return "std::cos(" + a + ")";
                case "tan(D)D": return "std::tan(" + a + ")";
                case "asin(D)D": return "std::asin(" + a + ")";
                case "acos(D)D": return "std::acos(" + a + ")";
                case "atan(D)D": return "std::atan(" + a + ")";
                case "exp(D)D": return "std::exp(" + a + ")";
                case "log(D)D": return "std::log(" + a + ")";
                case "log10(D)D": return "std::log10(" + a + ")";
                case "pow(DD)D": return "std::pow(" + arg(base, 0) + ", " + arg(base, 1) + ")";
                case "atan2(DD)D": return "std::atan2(" + arg(base, 0) + ", " + arg(base, 1) + ")";
                case "hypot(DD)D": return "std::hypot(" + arg(base, 0) + ", " + arg(base, 1) + ")";
                case "copySign(DD)D": return "std::copysign(" + arg(base, 0) + ", " + arg(base, 1) + ")";
                case "toRadians(D)D": return "(" + a + " * 0.017453292519943295)";
                case "toDegrees(D)D": return "(" + a + " * 57.29577951308232)";
                case "signum(D)D":
                    return "(" + a + " > 0.0 ? 1.0 : (" + a + " < 0.0 ? -1.0 : " + a + "))";
                default:
                    return null;
            }
        }

        private boolean doubleNegate(Frame<BasicValue> frame, int depth) {
            if (!stackIs(frame, depth - 1, Type.DOUBLE)) return false;
            String a = stackVar(depth - 1, Type.DOUBLE);
            statements.add(a + " = -" + a + ";");
            return true;
        }

        private boolean intShift(Frame<BasicValue> frame, int depth, String kind) {
            if (!stackIs(frame, depth - 2, Type.INT) || !stackIs(frame, depth - 1, Type.INT)) return false;
            String a = stackVar(depth - 2, Type.INT);
            String n = stackVar(depth - 1, Type.INT);
            switch (kind) {
                case "shl" -> statements.add(a + " = (jint)((chimera_u32)" + a + " << (" + n + " & 31));");
                case "ushr" -> statements.add(a + " = (jint)((chimera_u32)" + a + " >> (" + n + " & 31));");
                default -> statements.add(a + " = chimera_isar(" + a + ", " + n + ");");
            }
            return true;
        }

        private boolean longShift(Frame<BasicValue> frame, int depth, String kind) {
            if (!stackIs(frame, depth - 2, Type.LONG) || !stackIs(frame, depth - 1, Type.INT)) return false;
            String a = stackVar(depth - 2, Type.LONG);
            String n = stackVar(depth - 1, Type.INT);
            switch (kind) {
                case "shl" -> statements.add(a + " = (jlong)((chimera_u64)" + a + " << (" + n + " & 63));");
                case "ushr" -> statements.add(a + " = (jlong)((chimera_u64)" + a + " >> (" + n + " & 63));");
                default -> statements.add(a + " = chimera_lsar(" + a + ", " + n + ");");
            }
            return true;
        }

        private boolean widen(Frame<BasicValue> frame, int depth, int from, int to, String cast) {
            if (!stackIs(frame, depth - 1, from)) return false;
            statements.add(stackVar(depth - 1, to) + " = " + cast + stackVar(depth - 1, from) + ";");
            return true;
        }

        private boolean narrowCast(Frame<BasicValue> frame, int depth, int from, int to, String cast) {
            return widen(frame, depth, from, to, cast);
        }

        private boolean narrowingHelper(Frame<BasicValue> frame, int depth, int from, int to, String helper) {
            if (!stackIs(frame, depth - 1, from)) return false;
            statements.add(stackVar(depth - 1, to) + " = " + helper + "(" + stackVar(depth - 1, from) + ");");
            return true;
        }

        private boolean intNarrow(Frame<BasicValue> frame, int depth, String cast) {
            if (!stackIs(frame, depth - 1, Type.INT)) return false;
            String a = stackVar(depth - 1, Type.INT);
            statements.add(a + " = (jint)" + cast + a + ";");
            return true;
        }

        private boolean longCompare(Frame<BasicValue> frame, int depth) {
            if (!stackIs(frame, depth - 2, Type.LONG) || !stackIs(frame, depth - 1, Type.LONG)) return false;
            String a = stackVar(depth - 2, Type.LONG);
            String b = stackVar(depth - 1, Type.LONG);
            statements.add(stackVar(depth - 2, Type.INT) + " = (" + a + " < " + b + ") ? -1 : (("
                    + a + " > " + b + ") ? 1 : 0);");
            return true;
        }

        private boolean doubleCompare(Frame<BasicValue> frame, int depth, String helper) {
            if (!stackIs(frame, depth - 2, Type.DOUBLE) || !stackIs(frame, depth - 1, Type.DOUBLE)) return false;
            String a = stackVar(depth - 2, Type.DOUBLE);
            String b = stackVar(depth - 1, Type.DOUBLE);
            statements.add(stackVar(depth - 2, Type.INT) + " = " + helper + "(" + a + ", " + b + ");");
            return true;
        }

        private boolean returnValue(Frame<BasicValue> frame, int depth, int sort) {
            if (Type.getReturnType(method.desc).getSort() != sort) return false;
            if (!stackIs(frame, depth - 1, sort)) return false;
            statements.add("return " + stackVar(depth - 1, sort) + ";");
            return true;
        }

        private void assign(int depth, int sort, String literal) {
            statements.add(stackVar(depth, sort) + " = " + literal + ";");
        }

        private boolean stackIs(Frame<BasicValue> frame, int index, int sort) {
            return index >= 0 && index < frame.getStackSize() && sortOf(frame.getStack(index)) == sort;
        }

        private String stackVar(int depth, int sort) {
            String key = depth + ":" + sort;
            usedStack.add(key);
            return "s" + depth + "_" + letter(sort);
        }

        private String localVar(int slot, int sort) {
            String key = localKey(slot, sort);
            usedLocals.add(key);
            return varName(key);
        }

        private static String localKey(int slot, int sort) {
            return slot + ":" + sort;
        }

        private static String varName(String key) {
            int colon = key.indexOf(':');
            return "lv" + key.substring(0, colon) + "_" + letter(Integer.parseInt(key.substring(colon + 1)));
        }

        private static int sortOfKey(String key) {
            return Integer.parseInt(key.substring(key.indexOf(':') + 1));
        }

        private static int sortOf(BasicValue value) {
            if (value == null || value.getType() == null) return -1;
            int sort = value.getType().getSort();
            return sort == Type.INT || sort == Type.LONG || sort == Type.DOUBLE ? sort : -1;
        }

        private static String letter(int sort) {
            return switch (sort) {
                case Type.INT -> "i";
                case Type.LONG -> "l";
                case Type.DOUBLE -> "d";
                default -> throw new IllegalArgumentException("unsupported sort " + sort);
            };
        }

        private static String cppType(int sort) {
            return switch (sort) {
                case Type.INT -> "jint";
                case Type.LONG -> "jlong";
                case Type.DOUBLE -> "jdouble";
                default -> throw new IllegalArgumentException("unsupported sort " + sort);
            };
        }

        private static String intLiteral(int value) {
            return value == Integer.MIN_VALUE ? "(-2147483647 - 1)" : Integer.toString(value);
        }

        private static String longLiteral(long value) {
            return value == Long.MIN_VALUE ? "(-9223372036854775807LL - 1)" : value + "L";
        }
    }
}
