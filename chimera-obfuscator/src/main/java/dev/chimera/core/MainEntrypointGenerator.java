package dev.chimera.core;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * Generates the {@code main} entrypoint adapter. Fabric invokes main entrypoints after
 * {@code Bootstrap.initialize()}, which is the safe moment to register sunk natives and define
 * hidden classes for mods that touch Minecraft registries during static initialization.
 */
public final class MainEntrypointGenerator {

    public static final String INTERNAL_NAME = "dev/chimera/runtime/ChimeraMainEntrypoint";
    public static final String BINARY_NAME = "dev.chimera.runtime.ChimeraMainEntrypoint";
    private static final String INITIALIZER = "net/fabricmc/api/ModInitializer";

    private MainEntrypointGenerator() {
    }

    public static byte[] generate() {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL,
                INTERNAL_NAME, null, "java/lang/Object", new String[]{INITIALIZER});
        MethodVisitor init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(1, 1);
        init.visitEnd();
        MethodVisitor hook = writer.visitMethod(Opcodes.ACC_PUBLIC, "onInitialize", "()V", null, null);
        hook.visitCode();
        hook.visitMethodInsn(Opcodes.INVOKESTATIC, "dev/chimera/runtime/ChimeraMainBootstrap",
                "onInitialize", "()V", false);
        hook.visitInsn(Opcodes.RETURN);
        hook.visitMaxs(0, 1);
        hook.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }
}
