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
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** G7: --auth-gate must inject the preLaunch entrypoint and the gate classes. */
class AuthGateWiringTest {

    private static final String FABRIC_JSON = """
            {"schemaVersion":1,"id":"wurst","entrypoints":{"main":["a.B"]},"mixins":["w.mixins.json"]}
            """;

    @Test
    void engineInjectsPreLaunchGate(@TempDir Path work) throws Exception {
        Path input = work.resolve("in.jar");
        try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(input))) {
            out.putNextEntry(new ZipEntry("fabric.mod.json"));
            out.write(FABRIC_JSON.getBytes(StandardCharsets.UTF_8));
            out.closeEntry();
            out.putNextEntry(new ZipEntry("fixtures/Gated.class"));
            out.write(tinyClass());
            out.closeEntry();
        }
        Path output = work.resolve("out.jar");
        ChimeraConfig config = simple(input, output);
        config.authGate = true;
        new ChimeraEngine(config).run();

        try (ZipFile zip = new ZipFile(output.toFile())) {
            String json = new String(zip.getInputStream(zip.getEntry("fabric.mod.json")).readAllBytes(),
                    StandardCharsets.UTF_8);
            assertTrue(json.contains("preLaunch"), "preLaunch entrypoint must be injected");
            assertTrue(json.contains("dev.chimera.runtime.ChimeraPreLaunchEntrypoint"));
            assertTrue(json.contains("a.B"), "existing main entrypoint must survive");
            assertNotNull(zip.getEntry("dev/chimera/runtime/ChimeraPreLaunch.class"));
            assertNotNull(zip.getEntry("dev/chimera/runtime/ChimeraActivationPanel.class"));
            assertNotNull(zip.getEntry("dev/chimera/runtime/ChimeraPreLaunchEntrypoint.class"));
        }
    }

    @Test
    void missingFabricJsonFailsTheBuild(@TempDir Path work) throws Exception {
        Path input = work.resolve("in.jar");
        try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(input))) {
            out.putNextEntry(new ZipEntry("fixtures/Gated.class"));
            out.write(tinyClass());
            out.closeEntry();
        }
        ChimeraConfig config = simple(input, work.resolve("out.jar"));
        config.authGate = true;
        IllegalStateException error = assertThrows(IllegalStateException.class,
                () -> new ChimeraEngine(config).run());
        assertTrue(error.getMessage().contains("fabric.mod.json"), error.getMessage());
    }

    @Test
    void gateIsNotInstalledByDefault(@TempDir Path work) throws Exception {
        Path input = work.resolve("in.jar");
        try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(input))) {
            out.putNextEntry(new ZipEntry("fabric.mod.json"));
            out.write(FABRIC_JSON.getBytes(StandardCharsets.UTF_8));
            out.closeEntry();
            out.putNextEntry(new ZipEntry("fixtures/Gated.class"));
            out.write(tinyClass());
            out.closeEntry();
        }
        Path output = work.resolve("out.jar");
        new ChimeraEngine(simple(input, output)).run();
        try (ZipFile zip = new ZipFile(output.toFile())) {
            String json = new String(zip.getInputStream(zip.getEntry("fabric.mod.json")).readAllBytes(),
                    StandardCharsets.UTF_8);
            assertFalse(json.contains("preLaunch"));
        }
    }

    private static ChimeraConfig simple(Path input, Path output) {
        ChimeraConfig config = new ChimeraConfig();
        config.inputJar = input;
        config.outputJar = output;
        config.keyMaterial = Crypto.sha256("gate".getBytes(StandardCharsets.UTF_8));
        config.encryptStrings = false;
        config.fragmentMethods = false;
        config.nativeStubs = false;
        config.entangle = false;
        config.honeypot = false;
        config.vm = false;
        config.rename = false;
        config.integrityManifest = false;
        return config;
    }

    private static byte[] tinyClass() {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixtures/Gated", null, "java/lang/Object", null);
        MethodVisitor mv = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "run", "()I", null, null);
        mv.visitCode();
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(1, 0);
        mv.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }
}
