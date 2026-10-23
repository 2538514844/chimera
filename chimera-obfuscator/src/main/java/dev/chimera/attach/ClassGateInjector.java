package dev.chimera.attach;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * A2: per-class authorization gate (gray rollout).
 *
 * <p>Injects at the top of a class's {@code <clinit>}:</p>
 * <pre>
 *   ldc  &lt;id&gt;
 *   invokestatic &lt;runtime&gt;.nativeGateCheck(I)V
 * </pre>
 *
 * <p>Rationale (docs/HANDOVER-2026-10-22-SECURITY-B.md, "Hachimi"): a single global gate is one
 * boolean away from being bypassed. A per-class check means the decision has to be reproduced at
 * every gated class, and because the gate derives a different token per id, a patch that works for
 * one class teaches nothing about the next.</p>
 *
 * <p><b>Red team round 3 (2026-10-22): this used to be decorative.</b> The injected shape was
 * {@code invokestatic classGate(I)I; ifne ok; athrow}, so <i>any</i> non-zero token passed, and
 * because {@code classGate} was a three-line Java wrapper, patching that one method to
 * {@code return 1} cleared every gated class simultaneously. Both halves are gone now:</p>
 * <ul>
 *   <li>the call is {@code void} - there is no branch in the class body to flip;</li>
 *   <li>it targets the {@code native} method directly - there is no Java wrapper to rewrite;</li>
 *   <li>on denial the DLL terminates the process, so no verdict is ever returned to Java.</li>
 * </ul>
 *
 * <p>Constraints:</p>
 * <ul>
 *   <li>Only classes that already have a {@code <clinit>} are gated; adding one changes class
 *       initialization semantics and is not needed for the rollout.</li>
 *   <li>If the runtime owner cannot be resolved, nothing is injected (the licensed launch must never
 *       be broken by this) - decryption still fails closed without a handle.</li>
 *   <li>Any ASM failure returns the input unchanged.</li>
 * </ul>
 */
final class ClassGateInjector {

    /**
     * 1 in N classes. 50 yields ~23 selected, of which roughly half have a {@code <clinit>} -
     * about the 10-class gray batch agreed for the first rollout. Lowering it to 1 gates every
     * class (the end state), at the cost of ~1 JNI call per class at initialization.
     */
    private static final int MODULUS = 50;
    private static final String GATE_METHOD = "nativeGateCheck";
    private static final String GATE_DESC = "(I)V";

    private ClassGateInjector() {
    }

    /** Deterministic, name-independent selection so the rollout needs no class list. */
    static boolean selected(String internalName) {
        return internalName != null && Math.floorMod(internalName.hashCode(), MODULUS) == 0;
    }

    /** Stable per-class id (never 0, which is the "denied" value). */
    static int idFor(String internalName) {
        return Math.floorMod(internalName.hashCode(), 100_000) + 1;
    }

    /**
     * @param plain           class bytes (already decrypted and watermarked)
     * @param internalName    the class being transformed (only used for the id)
     * @param runtimeInternal internal name of the loaded {@code ChimeraRuntime} copy, or null
     * @return gated bytes, or {@code plain} when nothing was injected
     */
    static byte[] inject(byte[] plain, String internalName, String runtimeInternal) {
        if (plain == null || internalName == null || runtimeInternal == null
                || !selected(internalName)) {
            return plain;
        }
        return injectWithId(plain, idFor(internalName), runtimeInternal);
    }

    /** Same as {@link #inject} without the rollout filter; exposed for tests. */
    static byte[] injectWithId(byte[] plain, int id, String runtimeInternal) {
        if (plain == null || runtimeInternal == null) {
            return plain;
        }
        try {
            ClassReader reader = new ClassReader(plain);
            ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
            final boolean[] injected = {false};
            ClassVisitor visitor = new ClassVisitor(Opcodes.ASM9, writer) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                 String signature, String[] exceptions) {
                    MethodVisitor base = super.visitMethod(access, name, descriptor, signature,
                            exceptions);
                    if (base == null || !"<clinit>".equals(name)) {
                        return base;
                    }
                    injected[0] = true;
                    return new MethodVisitor(Opcodes.ASM9, base) {
                        @Override
                        public void visitCode() {
                            super.visitCode();
                            // Void call, no branch: the class body contains no verdict to flip and
                            // no label/frame bookkeeping to get wrong. On denial the DLL exits the
                            // process before this returns, so control never reaches the real
                            // <clinit> body.
                            super.visitLdcInsn(id);
                            super.visitMethodInsn(Opcodes.INVOKESTATIC, runtimeInternal,
                                    GATE_METHOD, GATE_DESC, false);
                        }
                    };
                }
            };
            reader.accept(visitor, 0);
            if (!injected[0]) {
                return plain;
            }
            byte[] gated = writer.toByteArray();
            AttachAgent.diag("class gate injected id=" + id);
            return gated;
        } catch (Throwable failure) {
            AttachAgent.diag("class gate skipped (" + failure + ")");
            return plain;
        }
    }
}
