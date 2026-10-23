package dev.chimera.attach;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * #19: per-licence watermark injection.
 *
 * <p>Runs on the plaintext a class body has just been decrypted into, and prepends
 * {@code LDC "CHMW1:<base64>"; POP} to a handful of its methods. The constant is the RSA-encrypted
 * licence payload built by {@code ChimeraRuntime.watermarkPayload()} (licence id, account, QQ
 * number, observed IP, launch timestamp), so a leaked build can be traced back to the licence it
 * was activated with.</p>
 *
 * <p>Design constraints, in order of priority:</p>
 * <ul>
 *   <li><b>Never break a launch.</b> Any failure returns the input unchanged: a watermark is
 *       evidence, not a gate.</li>
 *   <li><b>Cheap.</b> At most {@link #MAX_METHODS_PER_CLASS} methods per class, two instructions
 *       each, no stack effect (push then pop), so every existing StackMapTable frame stays
 *       valid - ASM recomputes offsets and maxStack, nothing else needs touching.</li>
 *   <li><b>Not in constructors.</b> Code before {@code super()} is legal but pointless risk;
 *       ordinary methods are enough for redundancy.</li>
 *   <li><b>Mixin classes are never seen here</b> - they are shipped as plaintext, so
 *       {@code ClassDecryptTransformer} returns before this runs (坑 4: mixin structure must not
 *       change).</li>
 * </ul>
 */
final class WatermarkInjector {

    /** Methods per class. A few per class is enough: stripping the mark means touching all of them. */
    private static final int MAX_METHODS_PER_CLASS = 4;

    private WatermarkInjector() {
    }

    /**
     * @param plain   decrypted class bytes
     * @param payload {@code CHMW1:...} constant, or {@code null} to return {@code plain}
     * @return watermarked class bytes, or {@code plain} when injection is impossible
     */
    static byte[] inject(byte[] plain, String payload) {
        if (plain == null || payload == null || payload.isEmpty()) {
            return plain;
        }
        try {
            ClassReader reader = new ClassReader(plain);
            // COMPUTE_MAXS only: frames are copied through (their labels are re-laid-out by ASM),
            // which avoids COMPUTE_FRAMES' need to load classes during transformation.
            ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
            int[] injected = {0};
            ClassVisitor visitor = new ClassVisitor(Opcodes.ASM9, writer) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                 String signature, String[] exceptions) {
                    MethodVisitor base = super.visitMethod(access, name, descriptor, signature,
                            exceptions);
                    if (base == null) {
                        return null;
                    }
                    boolean concrete = (access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) == 0;
                    boolean ordinary = !name.startsWith("<");
                    if (!concrete || !ordinary || injected[0] >= MAX_METHODS_PER_CLASS) {
                        return base;
                    }
                    injected[0]++;
                    return new MethodVisitor(Opcodes.ASM9, base) {
                        @Override
                        public void visitCode() {
                            super.visitCode();
                            super.visitLdcInsn(payload);
                            super.visitInsn(Opcodes.POP);
                        }
                    };
                }
            };
            reader.accept(visitor, 0);
            return writer.toByteArray();
        } catch (Throwable failure) {
            AttachAgent.diag("watermark inject skipped (" + failure + ")");
            return plain;
        }
    }
}
