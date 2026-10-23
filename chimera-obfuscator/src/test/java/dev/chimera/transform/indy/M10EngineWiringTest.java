package dev.chimera.transform.indy;

import dev.chimera.core.ChimeraConfig;
import dev.chimera.core.ChimeraEngine;
import dev.chimera.crypto.Crypto;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.lang.reflect.InvocationTargetException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Lead wiring check for M10: the engine must inject the bootstrap/registry/check-hook classes,
 * write the CHMI member table, rewrite call sites to {@code invokedynamic}, and the resulting jar
 * must link and execute correctly in an isolated class loader.
 */
class M10EngineWiringTest {

    @Test
    void engineRewritesCallsAndJarRunsThroughBootstrap(@TempDir Path work) throws Exception {
        Path input = work.resolve("input.jar");
        try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(input))) {
            out.putNextEntry(new ZipEntry("fixtures/M10Helper.class"));
            out.write(helperClass());
            out.closeEntry();
            out.putNextEntry(new ZipEntry("fixtures/M10Caller.class"));
            out.write(callerClass());
            out.closeEntry();
        }

        Path output = work.resolve("out.jar");
        ChimeraConfig cfg = new ChimeraConfig();
        cfg.inputJar = input;
        cfg.outputJar = output;
        cfg.keyMaterial = Crypto.sha256("m10-wiring".getBytes(StandardCharsets.UTF_8));
        cfg.encryptStrings = false;
        cfg.fragmentMethods = false;
        cfg.nativeStubs = false;
        cfg.entangle = false;
        cfg.honeypot = false;
        cfg.vm = false;
        cfg.rename = false;
        cfg.integrityManifest = false;
        cfg.indy = true;
        new ChimeraEngine(cfg).run();

        // Engine must have written the CHMI table and injected the runtime support classes.
        try (ZipFile zip = new ZipFile(output.toFile())) {
            assertNotNull(zip.getEntry("chimera/indy/members.bin"), "member table resource");
            assertNotNull(zip.getEntry("dev/chimera/transform/indy/ChimeraBootstrap.class"));
            assertNotNull(zip.getEntry("dev/chimera/transform/indy/MemberIdRegistry.class"));
        }

        // The caller must no longer contain a plain INVOKESTATIC to the helper.
        byte[] callerBytes;
        try (ZipFile zip = new ZipFile(output.toFile())) {
            callerBytes = zip.getInputStream(zip.getEntry("fixtures/M10Caller.class")).readAllBytes();
        }
        String constantPoolText = new String(callerBytes, StandardCharsets.ISO_8859_1);
        assertTrue(!constantPoolText.contains("fixtures/M10Helper"),
                "rewritten site keeps only opaque ids, so the helper owner must be gone");

        try (URLClassLoader loader = new URLClassLoader(
                new URL[]{output.toUri().toURL()}, ClassLoader.getPlatformClassLoader())) {
            Class<?> hookType = Class.forName("dev.chimera.transform.indy.CheckHook", true, loader);
            Object allow = hookType.getField("ALLOW").get(null);
            Class<?> bootstrap = Class.forName("dev.chimera.transform.indy.ChimeraBootstrap", true, loader);
            bootstrap.getMethod("installCheckHook", hookType).invoke(null, allow);

            Class<?> caller = Class.forName("fixtures.M10Caller", true, loader);
            assertEquals(30, caller.getMethod("run").invoke(null),
                    "invokedynamic call site must resolve through the member table and execute");
        }
    }

    @Test
    void deniedHookFailsClosed(@TempDir Path work) throws Exception {
        Path input = work.resolve("input.jar");
        try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(input))) {
            out.putNextEntry(new ZipEntry("fixtures/M10Helper.class"));
            out.write(helperClass());
            out.closeEntry();
            out.putNextEntry(new ZipEntry("fixtures/M10Caller.class"));
            out.write(callerClass());
            out.closeEntry();
        }
        Path output = work.resolve("out.jar");
        ChimeraConfig cfg = new ChimeraConfig();
        cfg.inputJar = input;
        cfg.outputJar = output;
        cfg.keyMaterial = Crypto.sha256("m10-wiring-deny".getBytes(StandardCharsets.UTF_8));
        cfg.encryptStrings = false;
        cfg.fragmentMethods = false;
        cfg.nativeStubs = false;
        cfg.entangle = false;
        cfg.honeypot = false;
        cfg.vm = false;
        cfg.rename = false;
        cfg.integrityManifest = false;
        cfg.indy = true;
        new ChimeraEngine(cfg).run();

        try (URLClassLoader loader = new URLClassLoader(
                new URL[]{output.toUri().toURL()}, ClassLoader.getPlatformClassLoader())) {
            Class<?> hookType = Class.forName("dev.chimera.transform.indy.CheckHook", true, loader);
            Object deny = hookType.getField("DENY").get(null);
            Class<?> bootstrap = Class.forName("dev.chimera.transform.indy.ChimeraBootstrap", true, loader);
            bootstrap.getMethod("installCheckHook", hookType).invoke(null, deny);

            Class<?> caller = Class.forName("fixtures.M10Caller", true, loader);
            InvocationTargetException error = org.junit.jupiter.api.Assertions.assertThrows(
                    InvocationTargetException.class, () -> caller.getMethod("run").invoke(null));
            Throwable cause = error.getCause();
            assertTrue(cause instanceof BootstrapMethodError || cause instanceof ExceptionInInitializerError,
                    "denied link must fail closed, got " + cause);
        }
    }

    private static byte[] helperClass() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixtures/M10Helper", null, "java/lang/Object", null);
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "add", "(II)I", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitVarInsn(Opcodes.ILOAD, 1);
        mv.visitInsn(Opcodes.IADD);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(2, 2);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] callerClass() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixtures/M10Caller", null, "java/lang/Object", null);
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "()I", null, null);
        mv.visitCode();
        mv.visitIntInsn(Opcodes.BIPUSH, 12);
        mv.visitIntInsn(Opcodes.BIPUSH, 18);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "fixtures/M10Helper", "add", "(II)I", false);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(2, 0);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }
}
