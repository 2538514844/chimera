package dev.chimera.core;

import dev.chimera.crypto.Crypto;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Phase B gate: the JVM verifier must reject invalid frames before an artifact ships. */
class BytecodeVerifierTest {

    @Test
    void acceptsAValidJar(@TempDir Path work) throws Exception {
        Path jar = jar(work.resolve("good.jar"), validClass(), null);
        assertTrue(BytecodeVerifier.verify(jar, List.of()).isEmpty());
    }

    @Test
    void rejectsBadReturnType(@TempDir Path work) throws Exception {
        Path jar = jar(work.resolve("bad.jar"), badClass(), null);
        List<BytecodeVerifier.Failure> failures = BytecodeVerifier.verify(jar, List.of());
        assertFalse(failures.isEmpty(), "invalid bytecode must be reported");
        assertEquals("fixtures.BadSubject", failures.get(0).className());
    }

    @Test
    void engineFailsTheBuildWhenVerificationFails(@TempDir Path work) throws Exception {
        Path input = jar(work.resolve("in.jar"), badClass(), null);
        ChimeraConfig config = new ChimeraConfig();
        config.inputJar = input;
        config.outputJar = work.resolve("out.jar");
        config.keyMaterial = Crypto.sha256("v".getBytes(StandardCharsets.UTF_8));
        config.encryptStrings = false;
        config.fragmentMethods = false;
        config.nativeStubs = false;
        config.entangle = false;
        config.honeypot = false;
        config.vm = false;
        config.rename = false;
        config.integrityManifest = false;
        config.verifyBytecode = true;
        assertThrows(Exception.class, () -> new ChimeraEngine(config).run());
    }

    @Test
    void enginePassesCleanFixtures(@TempDir Path work) throws Exception {
        Path input = jar(work.resolve("in.jar"), validClass(), null);
        ChimeraConfig config = new ChimeraConfig();
        config.inputJar = input;
        config.outputJar = work.resolve("out.jar");
        config.keyMaterial = Crypto.sha256("v".getBytes(StandardCharsets.UTF_8));
        config.encryptStrings = false;
        config.fragmentMethods = false;
        config.nativeStubs = false;
        config.entangle = false;
        config.honeypot = false;
        config.vm = false;
        config.rename = false;
        config.integrityManifest = false;
        config.verifyBytecode = true;
        new ChimeraEngine(config).run();
        assertTrue(Files.size(config.outputJar) > 0L);
    }

    private static Path jar(Path path, byte[] classBytes, byte[] ignored) throws Exception {
        try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(path))) {
            out.putNextEntry(new ZipEntry("fixtures/" + nameOf(classBytes) + ".class"));
            out.write(classBytes);
            out.closeEntry();
        }
        return path;
    }

    private static String nameOf(byte[] bytes) {
        return new org.objectweb.asm.ClassReader(bytes).getClassName().substring("fixtures/".length());
    }

    private static byte[] validClass() {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixtures/GoodSubject", null,
                "java/lang/Object", null);
        MethodVisitor mv = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "value", "()I", null, null);
        mv.visitCode();
        mv.visitIntInsn(Opcodes.BIPUSH, 7);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(1, 0);
        mv.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    /** Descriptor says int, bytecode returns a reference: the JVM verifier must reject it. */
    private static byte[] badClass() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixtures/BadSubject", null,
                "java/lang/Object", null);
        MethodVisitor mv = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "value", "()I", null, null);
        mv.visitCode();
        mv.visitInsn(Opcodes.ACONST_NULL);
        mv.visitInsn(Opcodes.ARETURN);
        mv.visitMaxs(1, 0);
        mv.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }
}
