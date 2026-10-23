package dev.chimera.runtime;

import dev.chimera.core.ChimeraConfig;
import dev.chimera.core.ChimeraEngine;
import dev.chimera.crypto.Crypto;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase 0 (C-01..C-05, C-11, C-15): release builds must be immune to diagnostic downgrades.
 *
 * <p>Covers the three layers: the env.dat build-kind flag written by the engine, the runtime
 * policy that ignores overrides in release, and the build-time gates (Fabric check, frame
 * strategy, unresolved frame hierarchy).</p>
 */
class ReleaseGateTest {

    private static final String[] DEBUG_PROPERTIES = {
            "chimera.runtime.hash.skip",
            "chimera.timing.windowThresholdMs",
            "chimera.timing.windowSize",
            "chimera.timing.debug",
            "chimera.vm.probe.mode",
            "chimera.vm.probeBudgetNanos",
            "chimera.vm.probe.debug"
    };

    @AfterEach
    void cleanup() {
        for (String key : DEBUG_PROPERTIES) {
            System.clearProperty(key);
        }
        DebugSwitches.configure(true);
    }

    // ---------------------------------------------------------------- runtime policy

    @Test
    void releaseBuildIgnoresDiagnosticOverrides() {
        DebugSwitches.configure(false);
        for (String key : DEBUG_PROPERTIES) {
            System.setProperty(key, "true");
        }
        System.setProperty("chimera.timing.windowThresholdMs", "1");
        assertTrue(DebugSwitches.release());
        assertNull(DebugSwitches.property("chimera.timing.windowThresholdMs"),
                "release builds must fall back to the default timing window");
        assertEquals(false, DebugSwitches.propertyTrue("chimera.runtime.hash.skip"),
                "release builds must never skip the runtime hash");
        assertEquals(false, DebugSwitches.propertyTrue("chimera.vm.probe.debug"),
                "release builds must not enable probe logging");
    }

    @Test
    void devBuildHonoursDiagnosticOverrides() {
        DebugSwitches.configure(true);
        System.setProperty("chimera.timing.windowSize", "7");
        System.setProperty("chimera.runtime.hash.skip", "true");
        assertEquals("7", DebugSwitches.property("chimera.timing.windowSize"));
        assertTrue(DebugSwitches.propertyTrue("chimera.runtime.hash.skip"));
        assertEquals(false, DebugSwitches.release());
    }

    @Test
    void unresolvedBuildKindDeniesDiagnosticOverrides() {
        DebugSwitches.resetForTests();
        System.setProperty("chimera.timing.windowConsecutive", "2");
        // SECURITY (audit 2026-10-22 #5): the default flipped from allow to deny. An artifact whose
        // build kind could not be resolved (no env.dat, unreadable marker) must not honour
        // overrides, otherwise deleting the marker resources downgrades a release artifact.
        assertNull(DebugSwitches.property("chimera.timing.windowConsecutive"),
                "an unresolved build kind must deny overrides");
        assertEquals(false, DebugSwitches.propertyTrue("chimera.runtime.hash.skip"),
                "an unresolved build kind must deny overrides");
    }

    // ---------------------------------------------------------------- env.dat build kind

    @Test
    void engineWritesBuildKindFlag(@TempDir Path work) throws Exception {
        assertEquals(1, envFlagsOf(buildJar(work, false, null)), "dev build => flag bit 0");
        byte[] key = Crypto.sha256("release-gate-test".getBytes(StandardCharsets.UTF_8));
        assertEquals(0, envFlagsOf(buildJar(work, true, key)), "release build => no dev flag");
    }

    // ---------------------------------------------------------------- build-time gates

    @Test
    void releaseRejectsDisabledFabricCheck() {
        ChimeraConfig cfg = baseConfig();
        cfg.release = true;
        cfg.resourceKeyMaterial = new byte[32];
        cfg.strictFabric = false;
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class, cfg::validate);
        assertTrue(error.getMessage().contains("--no-fabric-check"), error.getMessage());
    }

    @Test
    void releaseRejectsPreservedFramesWithControlFlow() {
        ChimeraConfig cfg = baseConfig();
        cfg.release = true;
        cfg.resourceKeyMaterial = new byte[32];
        cfg.preserveFrames = true;
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class, cfg::validate);
        assertTrue(error.getMessage().contains("StackMapTable"), error.getMessage());
    }

    @Test
    void releaseFailsOnUnresolvedFrameHierarchy(@TempDir Path work) throws Exception {
        Path input = work.resolve("unresolved.jar");
        try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(input))) {
            out.putNextEntry(new ZipEntry("fixtures/Pick.class"));
            out.write(pickClass());
            out.closeEntry();
        }
        ChimeraConfig cfg = simpleConfig(input, work.resolve("release.jar"));
        cfg.release = true;
        // Harden touches every class, forcing frame computation to resolve the missing types.
        cfg.harden = true;
        cfg.resourceKeyMaterial = Crypto.sha256("gate".getBytes(StandardCharsets.UTF_8));
        IllegalStateException error = assertThrows(IllegalStateException.class,
                () -> new ChimeraEngine(cfg).run());
        // The release gate now trips in the verifier stage (COMPUTE_FRAMES degrades to Object for
        // the missing supertype, so the class no longer verifies). Both paths are fail-closed; what
        // matters for the operator is that the message names the class and points at --classpath.
        assertTrue(error.getMessage().contains("JVM verifier rejected")
                || error.getMessage().contains("could not resolve"), error.getMessage());
        assertTrue(error.getMessage().contains("Pick"), error.getMessage());
        assertTrue(error.getMessage().contains("--classpath"), error.getMessage());

        // The same input is fine for a dev build: frames degrade to Object as before.
        ChimeraConfig dev = simpleConfig(input, work.resolve("dev.jar"));
        new ChimeraEngine(dev).run();
        assertTrue(Files.size(work.resolve("dev.jar")) > 0L);
    }

    @Test
    void shippedReleaseDllContainsNoDevBypassMarkers() throws Exception {
        Path dll = Path.of("native", "windows-x64", "chimera_auth.dll");
        Assumptions.assumeTrue(Files.isRegularFile(dll),
                "release DLL not built in this checkout (scripts/build-native-auth.ps1 -Configuration release)");
        String text = new String(Files.readAllBytes(dll), StandardCharsets.ISO_8859_1);
        for (String marker : new String[]{"CHIMERA_TEST_MODE", "CHIMERA_ALLOW_FRIDA",
                "nativeExpireHandleForTest"}) {
            assertEquals(-1, text.indexOf(marker),
                    "shipped release DLL must not embed the dev-only marker " + marker);
        }
    }

    // ---------------------------------------------------------------- fixtures

    private static ChimeraConfig baseConfig() {
        ChimeraConfig cfg = new ChimeraConfig();
        cfg.inputJar = Path.of("in.jar");
        cfg.outputJar = Path.of("out.jar");
        return cfg;
    }

    private static ChimeraConfig simpleConfig(Path input, Path output) {
        ChimeraConfig cfg = new ChimeraConfig();
        cfg.inputJar = input;
        cfg.outputJar = output;
        cfg.keyMaterial = Crypto.sha256("dev-key".getBytes(StandardCharsets.UTF_8));
        cfg.encryptStrings = false;
        cfg.fragmentMethods = false;
        cfg.nativeStubs = false;
        cfg.entangle = false;
        cfg.honeypot = false;
        cfg.vm = false;
        cfg.rename = false;
        cfg.integrityManifest = false;
        return cfg;
    }

    private static Path buildJar(Path work, boolean release, byte[] resourceKey) throws Exception {
        Path input = work.resolve(release ? "in-release.jar" : "in-dev.jar");
        try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(input))) {
            out.putNextEntry(new ZipEntry("fixtures/Tiny.class"));
            out.write(tinyClass());
            out.closeEntry();
        }
        Path output = work.resolve(release ? "out-release.jar" : "out-dev.jar");
        ChimeraConfig cfg = simpleConfig(input, output);
        cfg.release = release;
        cfg.resourceKeyMaterial = resourceKey;
        new ChimeraEngine(cfg).run();
        return output;
    }

    private static int envFlagsOf(Path jar) throws Exception {
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            ZipEntry entry = zip.getEntry("chimera/env.dat");
            assertTrue(entry != null, "engine must write chimera/env.dat");
            try (DataInputStream in = new DataInputStream(
                    new ByteArrayInputStream(zip.getInputStream(entry).readAllBytes()))) {
                assertEquals(0x43485631, in.readInt(), "CHV1 magic");
                assertEquals(2, in.readInt(), "environment record version must be 2");
                return in.readInt();
            }
        }
    }

    private static byte[] tinyClass() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixtures/Tiny", null, "java/lang/Object", null);
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "()I", null, null);
        mv.visitCode();
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(1, 1);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    /** Merges two unrelated types that are absent from the jar: frame computation cannot resolve them. */
    private static byte[] pickClass() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixtures/Pick", null, "java/lang/Object", null);
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "pick", "(Z)Ljava/lang/Object;", null, null);
        mv.visitCode();
        Label other = new Label();
        Label join = new Label();
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitJumpInsn(Opcodes.IFEQ, other);
        mv.visitTypeInsn(Opcodes.NEW, "org/example/MissingA");
        mv.visitInsn(Opcodes.DUP);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "org/example/MissingA", "<init>", "()V", false);
        mv.visitJumpInsn(Opcodes.GOTO, join);
        mv.visitLabel(other);
        mv.visitTypeInsn(Opcodes.NEW, "org/example/MissingB");
        mv.visitInsn(Opcodes.DUP);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "org/example/MissingB", "<init>", "()V", false);
        mv.visitLabel(join);
        mv.visitInsn(Opcodes.ARETURN);
        mv.visitMaxs(2, 1);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }
}
