package dev.chimera.core;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * S2: generates the {@code preLaunch} entrypoint that self-attaches the decryption agent before any
 * protected mod class is resolved.
 */
public final class AttachEntrypointGenerator {

    public static final String INTERNAL_NAME = "dev/chimera/runtime/ChimeraAttachEntrypoint";
    public static final String BINARY_NAME = "dev.chimera.runtime.ChimeraAttachEntrypoint";
    private static final String ENTRYPOINT_INTERFACE =
            "net/fabricmc/loader/api/entrypoint/PreLaunchEntrypoint";

    private AttachEntrypointGenerator() {
    }

    public static byte[] generate() {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL,
                INTERNAL_NAME, null, "java/lang/Object", new String[]{ENTRYPOINT_INTERFACE});
        MethodVisitor init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(1, 1);
        init.visitEnd();
        MethodVisitor hook = writer.visitMethod(Opcodes.ACC_PUBLIC, "onPreLaunch", "()V", null, null);
        hook.visitCode();
        hook.visitMethodInsn(Opcodes.INVOKESTATIC, "dev/chimera/runtime/ChimeraAttach",
                "install", "()V", false);
        hook.visitInsn(Opcodes.RETURN);
        hook.visitMaxs(0, 1);
        hook.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }
}
