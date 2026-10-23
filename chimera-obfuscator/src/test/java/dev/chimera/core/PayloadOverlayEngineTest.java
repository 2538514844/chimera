package dev.chimera.core;

import dev.chimera.crypto.Crypto;
import dev.chimera.transform.payload.PayloadPackager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** S5: the engine appends the encrypted CHPY overlay to a built native DLL. */
class PayloadOverlayEngineTest {

    @Test
    void engineWritesPackedDll(@TempDir Path work) throws Exception {
        Path input = work.resolve("in.jar");
        try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(input))) {
            out.putNextEntry(new ZipEntry("fixtures/Overlay.class"));
            out.write(tinyClass());
            out.closeEntry();
        }
        byte[] fakeDll = new byte[4096];
        new java.util.Random(7L).nextBytes(fakeDll);
        Path dll = work.resolve("chimera_auth.dll");
        Files.write(dll, fakeDll);

        ChimeraConfig config = simple(input, work.resolve("out.jar"));
        config.payloadOverlay = true;
        config.payloadDllPath = dll;
        new ChimeraEngine(config).run();

        Path packed = work.resolve("chimera_auth.dll.packed");
        assertTrue(Files.isRegularFile(packed), "packed DLL must be written");
        byte[] packedBytes = Files.readAllBytes(packed);
        assertTrue(packedBytes.length > fakeDll.length);
        assertTrue(PayloadPackager.verify(packedBytes));
        byte[] recovered = PayloadPackager.extract(packedBytes,
                config.encryptionKeyMaterial(), envSaltOf(config, work));
    }

    @Test
    void missingDllFailsTheBuild(@TempDir Path work) throws Exception {
        Path input = work.resolve("in.jar");
        try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(input))) {
            out.putNextEntry(new ZipEntry("fixtures/Overlay.class"));
            out.write(tinyClass());
            out.closeEntry();
        }
        ChimeraConfig config = simple(input, work.resolve("out.jar"));
        config.payloadOverlay = true;
        config.payloadDllPath = work.resolve("missing.dll");
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> new ChimeraEngine(config).run());
        assertTrue(error.getMessage().contains("DLL not found"), error.getMessage());
    }

    private static byte[] envSaltOf(ChimeraConfig config, Path work) throws Exception {
        // The engine uses a random per-build salt; the test only needs the extract path to run
        // with a non-null salt, so read it back from env.dat.
        try (var zip = new java.util.zip.ZipFile(config.outputJar.toFile())) {
            java.io.DataInputStream in = new java.io.DataInputStream(
                    new java.io.ByteArrayInputStream(
                            zip.getInputStream(zip.getEntry("chimera/env.dat")).readAllBytes()));
            in.readInt();
            int version = in.readInt();
            if (version >= 2) in.readInt();
            byte[] salt = new byte[in.readInt()];
            in.readFully(salt);
            return salt;
        }
    }

    private static ChimeraConfig simple(Path input, Path output) {
        ChimeraConfig config = new ChimeraConfig();
        config.inputJar = input;
        config.outputJar = output;
        config.keyMaterial = Crypto.sha256("overlay".getBytes(StandardCharsets.UTF_8));
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
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixtures/Overlay", null,
                "java/lang/Object", null);
        MethodVisitor mv = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "value", "()I", null, null);
        mv.visitCode();
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(1, 0);
        mv.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }
}
