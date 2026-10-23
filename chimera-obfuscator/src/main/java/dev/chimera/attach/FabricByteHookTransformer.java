package dev.chimera.attach;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import java.util.Set;

/**
 * Patches Fabric's class-byte readers so they return decrypted CHENC1 bodies before Fabric runs its
 * own ASM passes. Without this, {@code KnotClassDelegate.getPreMixinClassByteArray} feeds ciphertext
 * to {@code FabricTransformer} and fails with ArrayIndexOutOfBoundsException before defineClass.
 */
public final class FabricByteHookTransformer implements ClassFileTransformer {

    private static final String DELEGATE = "net/fabricmc/loader/impl/launch/knot/KnotClassDelegate";
    private static final String KNOT = "net/fabricmc/loader/impl/launch/knot/Knot";
    private static final String HOOK = "dev/chimera/attach/FabricHook";
    private static final Set<String> TARGETS = Set.of(DELEGATE, KNOT);

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain, byte[] classfileBuffer) {
        if (className == null || classfileBuffer == null || !TARGETS.contains(className)) {
            return null;
        }
        try {
            ClassReader reader = new ClassReader(classfileBuffer);
            // Frames must be recomputed: inserting a call before ARETURN changes the stack map.
            ClassWriter writer = new ClassWriter(reader,
                    ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
            final boolean[] changed = {false};
            ClassVisitor visitor = new ClassVisitor(Opcodes.ASM9, writer) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                 String signature, String[] exceptions) {
                    MethodVisitor delegate = super.visitMethod(access, name, descriptor, signature, exceptions);
                    boolean eligible = descriptor.startsWith("(Ljava/lang/String;")
                            && descriptor.endsWith(")[B");
                    if (!eligible) {
                        return delegate;
                    }
                    final boolean isStatic = (access & Opcodes.ACC_STATIC) != 0;
                    changed[0] = true;
                    return new MethodVisitor(Opcodes.ASM9, delegate) {
                        @Override
                        public void visitInsn(int opcode) {
                            if (opcode == Opcodes.ARETURN) {
                                super.visitVarInsn(Opcodes.ALOAD, isStatic ? 0 : 1);
                                super.visitInsn(Opcodes.SWAP);
                                super.visitMethodInsn(Opcodes.INVOKESTATIC, HOOK, "decrypt",
                                        "(Ljava/lang/String;[B)[B", false);
                            }
                            super.visitInsn(opcode);
                        }
                    };
                }
            };
            reader.accept(visitor, 0);
            if (!changed[0]) {
                return null;
            }
            AttachAgent.diag("patched fabric byte reader: " + className);
            return writer.toByteArray();
        } catch (Throwable failure) {
            AttachAgent.diag("fabric patch failed " + className + " -> " + failure);
            return null;
        }
    }
}
