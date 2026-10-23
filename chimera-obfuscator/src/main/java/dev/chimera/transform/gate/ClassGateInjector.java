package dev.chimera.transform.gate;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * Build-time injection of the per-class authorization gate.
 *
 * <p>The gate used to be injected by the attach agent at <b>run time</b>, right after a class body
 * was decrypted. That works for a live process, but it means the shipped bytes contain no gate at
 * all - so an attacker who decrypts the class bodies offline (which needs only the ResourceKey)
 * gets ungated bytecode, and a repacked jar never calls {@code nativeGateCheck}. Red team round 4
 * measured exactly that: 1347 dumped classes contained zero gate calls, and the "dump and repack"
 * crack was only stopped by an accident (780 classes still referenced the runtime for string
 * decryption).</p>
 *
 * <p>Injecting here - after renaming, before encryption - makes the gate part of the class body the
 * attacker must ship. A repack then carries the gate too, and without a live handle the DLL
 * terminates the process at the first gated class.</p>
 *
 * <p>Constraints carried over from the runtime injector: only classes that already have a
 * {@code <clinit>} are gated (adding one would change initialization semantics), the call is
 * {@code void} so there is no branch to flip, and any ASM failure leaves the class untouched rather
 * than breaking the build.</p>
 */
public final class ClassGateInjector {

    /**
     * 1 in N classes. 50 keeps the rollout at roughly the same nine classes as before; lowering it
     * to 1 gates every class (the end state) at the cost of one JNI call per class initialization.
     */
    private static final int MODULUS = 50;
    private static final String GATE_METHOD = "nativeGateCheck";
    private static final String GATE_DESC = "(I)V";

    private ClassGateInjector() {
    }

    /** Deterministic, name-independent selection so the rollout needs no class list. */
    public static boolean selected(String internalName) {
        return internalName != null && Math.floorMod(internalName.hashCode(), MODULUS) == 0;
    }

    /** Stable per-class id (never 0). */
    public static int idFor(String internalName) {
        return Math.floorMod(internalName.hashCode(), 100_000) + 1;
    }

    /**
     * @param plain           class bytes as they will be encrypted
     * @param internalName    the class's final (post-rename) internal name
     * @param runtimeInternal the runtime class's final internal name, or null to skip
     * @return the gated bytes, or {@code plain} unchanged
     */
    public static byte[] inject(byte[] plain, String internalName, String runtimeInternal) {
        if (plain == null || internalName == null || runtimeInternal == null
                || !selected(internalName)) {
            return plain;
        }
        return injectWithId(plain, idFor(internalName), runtimeInternal);
    }

    /** Same as {@link #inject} without the rollout filter; exposed for tests. */
    public static byte[] injectWithId(byte[] plain, int id, String runtimeInternal) {
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
                            // Void call, no branch: the class body holds no verdict to flip, and on
                            // denial the DLL exits the process before this returns.
                            super.visitLdcInsn(id);
                            super.visitMethodInsn(Opcodes.INVOKESTATIC, runtimeInternal,
                                    GATE_METHOD, GATE_DESC, false);
                        }
                    };
                }
            };
            reader.accept(visitor, 0);
            return injected[0] ? writer.toByteArray() : plain;
        } catch (Throwable failure) {
            // Never fail a build over one class; the gate is defence in depth, not the only layer.
            System.err.println("[chimera] class gate skipped (id=" + id + "): " + failure);
            return plain;
        }
    }
}
