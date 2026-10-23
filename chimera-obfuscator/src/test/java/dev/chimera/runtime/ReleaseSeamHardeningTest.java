package dev.chimera.runtime;

import dev.chimera.core.ChimeraConfig;
import dev.chimera.core.ChimeraEngine;
import dev.chimera.crypto.Crypto;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * SECURITY (audit 2026-10-22 #3/#5): the {@code *ForTests} seams must not be reachable from a
 * shipped artifact, and a shipped artifact must know it is protected from a build-time constant
 * instead of the editable {@code env.dat}.
 *
 * <p>Artifacts without a native payload (plain obfuscation, engine unit tests) keep the seams,
 * which is what the release-halt tests rely on to capture {@code halt(4)}.</p>
 */
class ReleaseSeamHardeningTest {

    @Test
    void payloadArtifactShipsHardenedBuildFlags(@org.junit.jupiter.api.io.TempDir Path work)
            throws Exception {
        Path jar = buildJarWithPayload(work);
        try (URLClassLoader loader = new URLClassLoader(new URL[]{jar.toUri().toURL()},
                ClassLoader.getPlatformClassLoader())) {
            Class<?> flags = Class.forName("dev.chimera.runtime.ChimeraBuildFlags", true, loader);
            assertEquals(false, readBoolean(flags, "TEST_SEAMS"),
                    "a payload-carrying artifact must ship with the test seams compiled out");
            assertEquals(true, readBoolean(flags, "PAYLOAD_REQUIRED"),
                    "a payload-carrying artifact must treat a missing payload as tampering");
        }
    }

    @Test
    void artifactWithoutPayloadKeepsTheSeamsForTests(@org.junit.jupiter.api.io.TempDir Path work)
            throws Exception {
        Path jar = buildJar(work, null);
        try (URLClassLoader loader = new URLClassLoader(new URL[]{jar.toUri().toURL()},
                ClassLoader.getPlatformClassLoader())) {
            Class<?> flags = Class.forName("dev.chimera.runtime.ChimeraBuildFlags", true, loader);
            assertEquals(true, readBoolean(flags, "TEST_SEAMS"),
                    "an artifact without a payload is not a protected artifact");
            assertEquals(false, readBoolean(flags, "PAYLOAD_REQUIRED"),
                    "an artifact without a payload cannot demand one");
        }
    }

    @Test
    void seamsAreInertWhenTheBuildCompiledThemOut() throws Exception {
        java.lang.reflect.Field flag = ChimeraBuildFlags.class.getDeclaredField("TEST_SEAMS");
        flag.setAccessible(true);
        java.lang.reflect.Field sink = ChimeraRuntime.class.getDeclaredField("haltSink");
        sink.setAccessible(true);
        java.lang.reflect.Field authorized = ChimeraPreLaunch.class.getDeclaredField("gateAuthorized");
        authorized.setAccessible(true);
        boolean original = flag.getBoolean(null);
        try {
            flag.setBoolean(null, false);
            assertFalse(ChimeraRuntime.testSeamsAllowed(), "seams must be off when compiled out");
            ChimeraRuntime.setHaltSinkForTests(code -> { });
            assertNull(sink.get(null), "the halt sink must stay unset in a hardened artifact");
            authorized.setBoolean(null, false);
            ChimeraPreLaunch.markAuthorizedForTests();
            assertEquals(false, authorized.getBoolean(null),
                    "markAuthorizedForTests must not authorize a hardened artifact");
        } finally {
            flag.setBoolean(null, original);
            sink.set(null, null);
            authorized.setBoolean(null, false);
        }
    }

    private static boolean readBoolean(Class<?> owner, String name) throws Exception {
        java.lang.reflect.Field field = owner.getDeclaredField(name);
        field.setAccessible(true);
        return field.getBoolean(null);
    }

    private static Path buildJarWithPayload(Path work) throws Exception {
        Path dll = work.resolve("fake.dll");
        Files.write(dll, new byte[]{'M', 'Z', 0, 0, 1, 2, 3, 4});
        return buildJar(work, dll);
    }

    private static Path buildJar(Path work, Path payload) throws Exception {
        Path input = work.resolve("in.jar");
        try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(input))) {
            out.putNextEntry(new ZipEntry("fixtures/Tiny.class"));
            out.write(tinyClass());
            out.closeEntry();
        }
        Path output = work.resolve("out.jar");
        ChimeraConfig cfg = new ChimeraConfig();
        cfg.inputJar = input;
        cfg.outputJar = output;
        cfg.keyMaterial = Crypto.sha256("seam-hardening".getBytes(StandardCharsets.UTF_8));
        cfg.encryptStrings = false;
        cfg.fragmentMethods = false;
        cfg.nativeStubs = false;
        cfg.entangle = false;
        cfg.honeypot = false;
        cfg.vm = false;
        cfg.rename = false;
        cfg.integrityManifest = false;
        cfg.embedDllPath = payload;
        new ChimeraEngine(cfg).run();
        try (ZipFile zip = new ZipFile(output.toFile())) {
            assertTrue(zip.getEntry("dev/chimera/runtime/ChimeraBuildFlags.class") != null,
                    "the build flags class must ship with the runtime");
        }
        return output;
    }

    private static byte[] tinyClass() {
        org.objectweb.asm.ClassWriter cw = new org.objectweb.asm.ClassWriter(0);
        cw.visit(org.objectweb.asm.Opcodes.V17, org.objectweb.asm.Opcodes.ACC_PUBLIC,
                "fixtures/Tiny", null, "java/lang/Object", null);
        org.objectweb.asm.MethodVisitor mv = cw.visitMethod(
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                "run", "()I", null, null);
        mv.visitCode();
        mv.visitInsn(org.objectweb.asm.Opcodes.ICONST_1);
        mv.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
        mv.visitMaxs(1, 1);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }
}
