package dev.chimera.transform;

import dev.chimera.core.TransformContext;
import dev.chimera.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.List;

/**
 * M2: entangles numeric computations with {@code ChimeraRuntime}'s key state.
 *
 * <p>Semantics on a valid key: every injected mask is the neutral element ({@code 0} for XOR,
 * {@code 1.0} for multiply), so the method is byte-for-byte equivalent in behaviour.</p>
 *
 * <p>Semantics on a missing/invalid key: the XOR mask is non-zero and the multiply mask is NaN,
 * so damage/gold/ratio values become negative, overflowed or NaN. No authorization exception is
 * thrown, which removes the "catch and skip" patch point.</p>
 */
public final class EntangleTransformer implements Transformer {

    private static final String ENTANGLE_DESC = "Ldev/chimera/annotations/ChimeraEntangle;";
    private static final String NATIVE_DESC = "Ldev/chimera/annotations/ChimeraNative;";
    private static final String RUNTIME = "dev/chimera/runtime/ChimeraRuntime";
    private static final int EXTRA_LOCALS = 8; // int(1) + long(2) + double(2) + float(1) + stamp(2)

    @Override
    public void transform(String internalName, ClassNode node, TransformContext ctx) throws Exception {
        if (!ctx.config.entangle) return;
        for (MethodNode method : new ArrayList<>(node.methods)) {
            if (!isCandidate(method)) continue;
            if (!hasAnnotation(method.invisibleAnnotations) && !hasAnnotation(method.visibleAnnotations)) continue;
            if (containsNative(method)) continue;

            List<AbstractInsnNode> targets = new ArrayList<>();
            boolean numeric = false;
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                int op = insn.getOpcode();
                if (op < 0) continue;
                if (isIntOp(op) || isLongOp(op) || isDoubleOp(op) || isFloatOp(op)
                        || op == Opcodes.IRETURN || op == Opcodes.LRETURN
                        || op == Opcodes.DRETURN || op == Opcodes.FRETURN
                        || op == Opcodes.ARETURN || op == Opcodes.RETURN) {
                    targets.add(insn);
                    if (op >= Opcodes.IADD && op <= Opcodes.LUSHR) numeric = true;
                }
            }
            if (targets.isEmpty() || !numeric) continue;

            int intSlot = method.maxLocals;
            int longSlot = intSlot + 1;
            int doubleSlot = longSlot + 2;
            int floatSlot = doubleSlot + 2;
            int stampSlot = floatSlot + 1;
            method.maxLocals += EXTRA_LOCALS;

            // Rewrite after the original instruction list was scanned, then prepend the prologue.
            for (AbstractInsnNode insn : targets) {
                int op = insn.getOpcode();
                InsnList injection = new InsnList();
                if (op == Opcodes.IRETURN || op == Opcodes.LRETURN || op == Opcodes.DRETURN
                        || op == Opcodes.FRETURN || op == Opcodes.ARETURN || op == Opcodes.RETURN) {
                    // Task 1: verify the session stamp captured on method entry; a hardcoded old
                    // stamp (or a nonce rotated mid-flight) poisons the runtime before returning.
                    injection.add(new VarInsnNode(Opcodes.LLOAD, stampSlot));
                    injection.add(new MethodInsnNode(Opcodes.INVOKESTATIC, RUNTIME,
                            "verifySessionStamp", "(J)V", false));
                    if (op == Opcodes.IRETURN) {
                        injection.add(new MethodInsnNode(Opcodes.INVOKESTATIC, RUNTIME,
                                "maskIntResult", "(I)I", false));
                    } else if (op == Opcodes.LRETURN) {
                        injection.add(new MethodInsnNode(Opcodes.INVOKESTATIC, RUNTIME,
                                "maskLongResult", "(J)J", false));
                    } else if (op == Opcodes.DRETURN) {
                        injection.add(new MethodInsnNode(Opcodes.INVOKESTATIC, RUNTIME, "doubleMask", "()D", false));
                        injection.add(new org.objectweb.asm.tree.InsnNode(Opcodes.DMUL));
                    } else if (op == Opcodes.FRETURN) {
                        injection.add(new MethodInsnNode(Opcodes.INVOKESTATIC, RUNTIME, "floatMask", "()F", false));
                        injection.add(new org.objectweb.asm.tree.InsnNode(Opcodes.FMUL));
                    }
                } else if (isIntOp(op)) {
                    injection.add(new VarInsnNode(Opcodes.ILOAD, intSlot));
                    injection.add(new org.objectweb.asm.tree.InsnNode(Opcodes.IXOR));
                } else if (isLongOp(op)) {
                    injection.add(new VarInsnNode(Opcodes.LLOAD, longSlot));
                    injection.add(new org.objectweb.asm.tree.InsnNode(Opcodes.LXOR));
                } else if (isDoubleOp(op)) {
                    injection.add(new VarInsnNode(Opcodes.DLOAD, doubleSlot));
                    injection.add(new org.objectweb.asm.tree.InsnNode(Opcodes.DMUL));
                } else if (isFloatOp(op)) {
                    injection.add(new VarInsnNode(Opcodes.FLOAD, floatSlot));
                    injection.add(new org.objectweb.asm.tree.InsnNode(Opcodes.FMUL));
                }
                if (op == Opcodes.IRETURN || op == Opcodes.LRETURN || op == Opcodes.DRETURN
                        || op == Opcodes.FRETURN || op == Opcodes.ARETURN || op == Opcodes.RETURN) {
                    // The return value is on the stack: insert the final mask *before* the return,
                    // otherwise the guaranteed sign-flip/NaN would be unreachable code.
                    method.instructions.insertBefore(insn, injection);
                } else {
                    method.instructions.insert(insn, injection);
                }
            }

            InsnList prologue = new InsnList();
            prologue.add(new MethodInsnNode(Opcodes.INVOKESTATIC, RUNTIME, "intMask", "()I", false));
            prologue.add(new VarInsnNode(Opcodes.ISTORE, intSlot));
            prologue.add(new MethodInsnNode(Opcodes.INVOKESTATIC, RUNTIME, "longMask", "()J", false));
            prologue.add(new VarInsnNode(Opcodes.LSTORE, longSlot));
            prologue.add(new MethodInsnNode(Opcodes.INVOKESTATIC, RUNTIME, "doubleMask", "()D", false));
            prologue.add(new VarInsnNode(Opcodes.DSTORE, doubleSlot));
            prologue.add(new MethodInsnNode(Opcodes.INVOKESTATIC, RUNTIME, "floatMask", "()F", false));
            prologue.add(new VarInsnNode(Opcodes.FSTORE, floatSlot));
            prologue.add(new MethodInsnNode(Opcodes.INVOKESTATIC, RUNTIME, "sessionStamp", "()J", false));
            prologue.add(new VarInsnNode(Opcodes.LSTORE, stampSlot));
            method.instructions.insert(prologue);

            removeAnnotation(method);
            // Purely linear injection: branch structure is unchanged, so the engine would keep
            // the original StackMapTable and the verifier would reject the new locals
            // ("Bad local variable type"). Force recomputation for this class.
            ctx.markFramesRequired(node.name != null ? node.name : internalName);
            ctx.stats.entangledMethods++;
        }
    }

    private static boolean isCandidate(MethodNode m) {
        if ((m.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) return false;
        return !"<init>".equals(m.name) && !"<clinit>".equals(m.name);
    }

    private static boolean hasAnnotation(List<AnnotationNode> annotations) {
        if (annotations == null) return false;
        for (AnnotationNode a : annotations) if (ENTANGLE_DESC.equals(a.desc)) return true;
        return false;
    }

    private static boolean containsNative(MethodNode m) {
        return hasAnnotation(m.invisibleAnnotations, NATIVE_DESC) || hasAnnotation(m.visibleAnnotations, NATIVE_DESC);
    }

    private static boolean hasAnnotation(List<AnnotationNode> annotations, String desc) {
        if (annotations == null) return false;
        for (AnnotationNode a : annotations) if (desc.equals(a.desc)) return true;
        return false;
    }

    private static void removeAnnotation(MethodNode m) {
        if (m.invisibleAnnotations != null) m.invisibleAnnotations.removeIf(a -> ENTANGLE_DESC.equals(a.desc));
        if (m.visibleAnnotations != null) m.visibleAnnotations.removeIf(a -> ENTANGLE_DESC.equals(a.desc));
    }

    private static boolean isIntOp(int op) {
        return op == Opcodes.IADD || op == Opcodes.ISUB || op == Opcodes.IMUL || op == Opcodes.IDIV
                || op == Opcodes.IREM || op == Opcodes.INEG || op == Opcodes.ISHL || op == Opcodes.ISHR
                || op == Opcodes.IUSHR || op == Opcodes.IAND || op == Opcodes.IOR || op == Opcodes.IXOR;
    }

    private static boolean isLongOp(int op) {
        return op == Opcodes.LADD || op == Opcodes.LSUB || op == Opcodes.LMUL || op == Opcodes.LDIV
                || op == Opcodes.LREM || op == Opcodes.LNEG || op == Opcodes.LSHL || op == Opcodes.LSHR
                || op == Opcodes.LUSHR || op == Opcodes.LAND || op == Opcodes.LOR || op == Opcodes.LXOR;
    }

    private static boolean isDoubleOp(int op) {
        return op == Opcodes.DADD || op == Opcodes.DSUB || op == Opcodes.DMUL || op == Opcodes.DDIV
                || op == Opcodes.DREM || op == Opcodes.DNEG;
    }

    private static boolean isFloatOp(int op) {
        return op == Opcodes.FADD || op == Opcodes.FSUB || op == Opcodes.FMUL || op == Opcodes.FDIV
                || op == Opcodes.FREM || op == Opcodes.FNEG;
    }
}
