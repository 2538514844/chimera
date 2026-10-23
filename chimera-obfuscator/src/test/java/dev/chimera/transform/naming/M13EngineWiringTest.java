package dev.chimera.transform.naming;

import dev.chimera.core.ChimeraConfig;
import dev.chimera.core.ChimeraEngine;
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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Lead wiring check: {@link ChimeraEngine} must run the M13 pre-pass before any transform and
 * write invisible names into the output jar. The transformer itself is covered by
 * {@link InvisibleNameTransformerTest}.
 */
class M13EngineWiringTest {

    @Test
    void engineAppliesInvisibleNaming(@TempDir Path work) throws Exception {
        Path input = work.resolve("input.jar");
        try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(input))) {
            out.putNextEntry(new ZipEntry("fixtures/M13Target.class"));
            out.write(targetClass());
            out.closeEntry();
        }
        Path output = work.resolve("out.jar");
        ChimeraConfig cfg = new ChimeraConfig();
        cfg.inputJar = input;
        cfg.outputJar = output;
        cfg.keyMaterial = Crypto.sha256("m13-wiring".getBytes(StandardCharsets.UTF_8));
        cfg.encryptStrings = false;
        cfg.fragmentMethods = false;
        cfg.nativeStubs = false;
        cfg.entangle = false;
        cfg.honeypot = false;
        cfg.vm = false;
        cfg.rename = false;
        cfg.integrityManifest = false;
        cfg.invisibleNaming = true;
        new ChimeraEngine(cfg).run();

        boolean foundInvisible = false;
        try (ZipFile zip = new ZipFile(output.toFile())) {
            var entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                if (name.endsWith(".class") && InvisibleNames.containsInvisible(name)) {
                    foundInvisible = true;
                    assertTrue(name.contains("M13Target"), "original name kept as prefix: " + name);
                }
            }
            assertNotNull(zip.getEntry("chimera/env.dat"));
        }
        assertTrue(foundInvisible, "engine must apply the M13 invisible-naming pre-pass");
    }

    private static byte[] targetClass() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixtures/M13Target", null, "java/lang/Object", null);
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "value", "()I", null, null);
        mv.visitCode();
        mv.visitIntInsn(Opcodes.BIPUSH, 7);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(1, 0);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }
}
