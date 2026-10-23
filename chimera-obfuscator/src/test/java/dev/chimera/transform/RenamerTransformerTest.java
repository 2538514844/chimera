package dev.chimera.transform;

import dev.chimera.core.ChimeraConfig;
import dev.chimera.core.ChimeraEngine;
import dev.chimera.core.Stats;
import dev.chimera.crypto.Crypto;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;

/** M7: opt-in renaming plus the build-time Fabric/Mixin/entrypoint safety gate. */
class RenamerTransformerTest {

    private static final String RENAME = "Ldev/chimera/annotations/ChimeraRename;";
    private static final String MIXIN = "Lorg/spongepowered/asm/mixin/Mixin;";

    private static ChimeraConfig config(Path in, Path out) {
        ChimeraConfig cfg = new ChimeraConfig();
        cfg.inputJar = in;
        cfg.outputJar = out;
        cfg.keyMaterial = new byte[32];
        cfg.rename = true;
        cfg.strictFabric = true;
        cfg.encryptStrings = false;
        cfg.fragmentMethods = false;
        cfg.nativeStubs = false;
        cfg.entangle = false;
        cfg.honeypot = false;
        cfg.vm = false;
        cfg.integrityManifest = false;
        return cfg;
    }

    private static Path buildJar(Path work, Map<String, byte[]> classes, Map<String, byte[]> resources)
            throws Exception {
        Path jar = work.resolve("rename-in.jar");
        Files.createDirectories(work);
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(jar))) {
            for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
                zos.putNextEntry(new ZipEntry(entry.getKey()));
                zos.write(entry.getValue());
                zos.closeEntry();
            }
            for (Map.Entry<String, byte[]> entry : resources.entrySet()) {
                zos.putNextEntry(new ZipEntry(entry.getKey()));
                zos.write(entry.getValue());
                zos.closeEntry();
            }
        }
        return jar;
    }

    private static byte[] makeClass(String name, int access, Consumer<ClassWriter> body) {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, access, name, null, "java/lang/Object", null);
        body.accept(cw);
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static void annotate(ClassVisitor visitor, String descriptor) {
        AnnotationVisitor annotation = visitor.visitAnnotation(descriptor, true);
        annotation.visitEnd();
    }

    private static void annotate(MethodVisitor visitor, String descriptor) {
        AnnotationVisitor annotation = visitor.visitAnnotation(descriptor, true);
        annotation.visitEnd();
    }

    private static byte[] damageCalc() {
        return makeClass("fixtures/dto/DamageCalc", Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL, cw -> {
            annotate(cw, RENAME);
            cw.visitField(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "BASE", "I", null, null).visitEnd();
            MethodVisitor compute = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                    "compute", "(I)I", null, null);
            annotate(compute, RENAME);
            compute.visitCode();
            compute.visitVarInsn(Opcodes.ILOAD, 0);
            compute.visitIntInsn(Opcodes.BIPUSH, 3);
            compute.visitInsn(Opcodes.IMUL);
            compute.visitIntInsn(Opcodes.BIPUSH, 1);
            compute.visitInsn(Opcodes.IADD);
            compute.visitInsn(Opcodes.IRETURN);
            compute.visitMaxs(2, 1);
            compute.visitEnd();
            MethodVisitor helper = cw.visitMethod(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
                    "helper", "()I", null, null);
            annotate(helper, RENAME);
            helper.visitCode();
            helper.visitIntInsn(Opcodes.BIPUSH, 7);
            helper.visitInsn(Opcodes.IRETURN);
            helper.visitMaxs(1, 0);
            helper.visitEnd();
        });
    }

    private static byte[] caller() {
        return makeClass("fixtures/dto/Caller", Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL, cw -> {
            MethodVisitor call = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                    "call", "(I)I", null, null);
            call.visitCode();
            call.visitVarInsn(Opcodes.ILOAD, 0);
            call.visitMethodInsn(Opcodes.INVOKESTATIC, "fixtures/dto/DamageCalc",
                    "compute", "(I)I", false);
            call.visitInsn(Opcodes.IRETURN);
            call.visitMaxs(1, 1);
            call.visitEnd();
        });
    }

    private static byte[] mcLogic() {
        return makeClass("fixtures/dto/McLogic", Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL, cw -> {
            annotate(cw, RENAME);
            MethodVisitor tick = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                    "tick", "(Lnet/minecraft/client/Minecraft;)I", null, null);
            tick.visitCode();
            tick.visitInsn(Opcodes.ICONST_0);
            tick.visitInsn(Opcodes.IRETURN);
            tick.visitMaxs(1, 1);
            tick.visitEnd();
        });
    }

    private static byte[] mixinLogic() {
        return makeClass("fixtures/dto/MixinLogic", Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL, cw -> {
            annotate(cw, RENAME);
            annotate(cw, MIXIN);
            MethodVisitor enter = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                    "enter", "()I", null, null);
            enter.visitCode();
            enter.visitInsn(Opcodes.ICONST_1);
            enter.visitInsn(Opcodes.IRETURN);
            enter.visitMaxs(1, 0);
            enter.visitEnd();
        });
    }

    private static byte[] entryLogic() {
        return makeClass("fixtures/dto/EntryLogic", Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL, cw -> {
            annotate(cw, RENAME);
            MethodVisitor enter = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                    "enter", "()I", null, null);
            enter.visitCode();
            enter.visitInsn(Opcodes.ICONST_2);
            enter.visitInsn(Opcodes.IRETURN);
            enter.visitMaxs(1, 0);
            enter.visitEnd();
        });
    }

    private static byte[] unannotatedMcAccess() {
        return makeClass("fixtures/dto/McAccess", Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL, cw -> {
            MethodVisitor touch = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                    "touch", "(Lnet/minecraft/client/Minecraft;)V", null, null);
            touch.visitCode();
            touch.visitInsn(Opcodes.RETURN);
            touch.visitMaxs(0, 1);
            touch.visitEnd();
        });
    }

    @Test
    void renamesAnnotatedClassAndMethodAndRewritesCallSites() throws Exception {
        Path work = Files.createTempDirectory("chimera-rename-ok");
        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put("fixtures/dto/DamageCalc.class", damageCalc());
        classes.put("fixtures/dto/Caller.class", caller());
        Path in = buildJar(work, classes, Map.of());
        Path out = work.resolve("ring.jar");
        Stats stats = new ChimeraEngine(config(in, out)).run();
        assertEquals(1, stats.renamedClasses, "one class must be renamed");
        assertEquals(2, stats.renamedMethods, "two marked methods must be renamed");

        Map<String, byte[]> entries = readJar(out);
        assertTrue(entries.containsKey("fixtures/dto/a$1.class"), entries.keySet().toString());
        assertFalse(entries.containsKey("fixtures/dto/DamageCalc.class"));

        ClassNode callerNode = new ClassNode();
        new ClassReader(entries.get("fixtures/dto/Caller.class")).accept(callerNode, 0);
        MethodNode call = callerNode.methods.stream()
                .filter(m -> m.name.equals("call")).findFirst().orElseThrow();
        boolean found = false;
        for (var insn : call.instructions) {
            if (insn instanceof MethodInsnNode methodInsn) {
                assertEquals("fixtures/dto/a$1", methodInsn.owner, "call site owner must be remapped");
                assertEquals("m$1", methodInsn.name, "call site method must be remapped");
                found = true;
            }
        }
        assertTrue(found, "caller must still call compute");

        assertFalse(new String(entries.get("fixtures/dto/a$1.class"), StandardCharsets.ISO_8859_1)
                .contains("ChimeraRename"), "marker annotation must be stripped");

        try (URLClassLoader loader = new URLClassLoader(new URL[]{out.toUri().toURL()},
                ClassLoader.getPlatformClassLoader())) {
            Class<?> callerClass = Class.forName("fixtures.dto.Caller", true, loader);
            assertEquals(16, callerClass.getMethod("call", int.class).invoke(null, 5));
        }
    }

    @Test
    void renameIntegratesWithVmAndIntegrityManifest() throws Exception {
        Path work = Files.createTempDirectory("chimera-rename-vm");
        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put("fixtures/dto/RenamedVm.class", renamedVm());
        classes.put("fixtures/dto/CallerVm.class", callerVm());
        Path in = buildJar(work, classes, Map.of());
        Path out = work.resolve("rename-vm.jar");
        ChimeraConfig cfg = config(in, out);
        cfg.keyMaterial = Crypto.sha256("rename-integration-key".getBytes(StandardCharsets.UTF_8));
        cfg.encryptStrings = true;
        cfg.fragmentMethods = true;
        cfg.entangle = true;
        cfg.vm = true;
        cfg.integrityManifest = true;
        new ChimeraEngine(cfg).run();

        Map<String, byte[]> entries = readJar(out);
        assertTrue(entries.containsKey("fixtures/dto/a$1.class"), entries.keySet().toString());
        assertEquals(1, countResources(entries, "chimera/vm/vm_"), "VM program must be emitted");
        assertTrue(countResources(entries, "chimera/chunks/chunk_") >= 1,
                "M3 fragment chunk must be emitted after M7 renamed the owner");
        assertTrue(entries.keySet().stream().noneMatch(name -> name.contains("$chimera$")),
                "M3 synthetic classes must never leak into the output jar / M7 must not rename them");
        String previous = System.getProperty("chimera.contentKey");
        System.setProperty("chimera.contentKey", "rename-integration-key");
        try (URLClassLoader loader = new URLClassLoader(new URL[]{out.toUri().toURL()},
                ClassLoader.getPlatformClassLoader())) {
            Class<?> caller = Class.forName("fixtures.dto.CallerVm", true, loader);
            assertEquals(9, caller.getMethod("callVm", int.class).invoke(null, 5));
            assertEquals(10, caller.getMethod("callProtected", int.class).invoke(null, 5),
                    "fragment created from the renamed owner must still load and run");
        } finally {
            if (previous == null) {
                System.clearProperty("chimera.contentKey");
            } else {
                System.setProperty("chimera.contentKey", previous);
            }
        }
    }

    private static byte[] renamedVm() {
        return makeClass("fixtures/dto/RenamedVm", Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL, cw -> {
            annotate(cw, RENAME);
            MethodVisitor vm = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                    "vmAdd", "(I)I", null, null);
            annotate(vm, "Ldev/chimera/annotations/ChimeraVM;");
            vm.visitCode();
            vm.visitVarInsn(Opcodes.ILOAD, 0);
            vm.visitIntInsn(Opcodes.BIPUSH, 4);
            vm.visitInsn(Opcodes.IADD);
            vm.visitInsn(Opcodes.IRETURN);
            vm.visitMaxs(2, 1);
            vm.visitEnd();

            // A6: M3 runs after M7, so the fragment's synthetic class is built from the renamed
            // owner name. Its bootstrap must still resolve.
            MethodVisitor protectedMethod = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                    "protectedAdd", "(I)I", null, null);
            annotate(protectedMethod, "Ldev/chimera/annotations/ChimeraProtected;");
            protectedMethod.visitCode();
            protectedMethod.visitVarInsn(Opcodes.ILOAD, 0);
            protectedMethod.visitIntInsn(Opcodes.BIPUSH, 5);
            protectedMethod.visitInsn(Opcodes.IADD);
            protectedMethod.visitInsn(Opcodes.IRETURN);
            protectedMethod.visitMaxs(2, 1);
            protectedMethod.visitEnd();
        });
    }

    private static byte[] callerVm() {
        return makeClass("fixtures/dto/CallerVm", Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL, cw -> {
            MethodVisitor call = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                    "callVm", "(I)I", null, null);
            call.visitCode();
            call.visitVarInsn(Opcodes.ILOAD, 0);
            call.visitMethodInsn(Opcodes.INVOKESTATIC, "fixtures/dto/RenamedVm",
                    "vmAdd", "(I)I", false);
            call.visitInsn(Opcodes.IRETURN);
            call.visitMaxs(1, 1);
            call.visitEnd();

            MethodVisitor callProtected = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                    "callProtected", "(I)I", null, null);
            callProtected.visitCode();
            callProtected.visitVarInsn(Opcodes.ILOAD, 0);
            callProtected.visitMethodInsn(Opcodes.INVOKESTATIC, "fixtures/dto/RenamedVm",
                    "protectedAdd", "(I)I", false);
            callProtected.visitInsn(Opcodes.IRETURN);
            callProtected.visitMaxs(1, 1);
            callProtected.visitEnd();
        });
    }

    private static int countResources(Map<String, byte[]> entries, String prefix) {
        int count = 0;
        for (String name : entries.keySet()) {
            if (name.startsWith(prefix)) {
                count++;
            }
        }
        return count;
    }

    @Test
    void rejectsAnnotatedClassThatReferencesMinecraftTypes() throws Exception {
        Path work = Files.createTempDirectory("chimera-rename-mc");
        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put("fixtures/dto/McLogic.class", mcLogic());
        Path in = buildJar(work, classes, Map.of());
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> new ChimeraEngine(config(in, work.resolve("bad.jar"))).run());
        assertTrue(error.getMessage().contains("net/minecraft/"), error.getMessage());
    }

    @Test
    void rejectsAnnotatedMixinClass() throws Exception {
        Path work = Files.createTempDirectory("chimera-rename-mixin");
        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put("fixtures/dto/MixinLogic.class", mixinLogic());
        Path in = buildJar(work, classes, Map.of());
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> new ChimeraEngine(config(in, work.resolve("bad.jar"))).run());
        assertTrue(error.getMessage().contains("Mixin"), error.getMessage());
    }

    @Test
    void rejectsClassRegisteredAsFabricEntrypoint() throws Exception {
        Path work = Files.createTempDirectory("chimera-rename-entrypoint");
        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put("fixtures/dto/EntryLogic.class", entryLogic());
        String modJson = "{\"schemaVersion\":1,\"id\":\"test\",\"version\":\"1.0.0\","
                + "\"entrypoints\":{\"main\":[\"fixtures.dto.EntryLogic\"]}}";
        Map<String, byte[]> resources = Map.of("fabric.mod.json",
                modJson.getBytes(StandardCharsets.UTF_8));
        Path in = buildJar(work, classes, resources);
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> new ChimeraEngine(config(in, work.resolve("bad.jar"))).run());
        assertTrue(error.getMessage().contains("fabric.mod.json"), error.getMessage());
    }

    @Test
    void leavesUnannotatedMinecraftAccessAlone() throws Exception {
        Path work = Files.createTempDirectory("chimera-rename-skip");
        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put("fixtures/dto/McAccess.class", unannotatedMcAccess());
        Path in = buildJar(work, classes, Map.of());
        new ChimeraEngine(config(in, work.resolve("ok.jar"))).run();
        Map<String, byte[]> entries = readJar(work.resolve("ok.jar"));
        assertTrue(entries.containsKey("fixtures/dto/McAccess.class"),
                "unannotated classes must not be renamed");
    }

    private static Map<String, byte[]> readJar(Path jar) throws Exception {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            var en = zip.entries();
            while (en.hasMoreElements()) {
                ZipEntry entry = en.nextElement();
                if (!entry.isDirectory()) {
                    entries.put(entry.getName(), zip.getInputStream(entry).readAllBytes());
                }
            }
        }
        return entries;
    }
}
