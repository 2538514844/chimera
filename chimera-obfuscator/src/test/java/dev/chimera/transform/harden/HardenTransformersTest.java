package dev.chimera.transform.harden;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HardenTransformersTest {

    private static byte[] sampleClass(String name, boolean mixin) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, name, null, "java/lang/Object", null);
        if (mixin) {
            cw.visitAnnotation("Lorg/spongepowered/asm/mixin/Mixin;", true).visitEnd();
        }
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "add", "(II)I", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitVarInsn(Opcodes.ILOAD, 1);
        mv.visitInsn(Opcodes.IADD);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static ClassNode node(byte[] bytes) {
        ClassNode cn = new ClassNode();
        new ClassReader(bytes).accept(cn, 0);
        return cn;
    }

    @Test
    void poisonMakesJavapCrashButClassStillRuns(@TempDir Path tmp) throws Exception {
        ClassNode cn = node(sampleClass("demo/Plain", false));
        StructuralPoisonTransformer.Stats stats =
                StructuralPoisonTransformer.transform(List.of(cn), StructuralPoisonTransformer.Options.defaults());
        assertEquals(1, stats.classes());
        assertTrue(stats.invalidSignatures() >= 2, "class/method signature should be poisoned");
        assertTrue(stats.fakeRefs() == 1);
        assertTrue(stats.dummyMethods() == 8);
        assertTrue(stats.constants() == 24);

        ClassWriter cw = new ClassWriter(0);
        cn.accept(cw);
        byte[] transformed = cw.toByteArray();
        assertNotNull(node(transformed), "ASM must still parse the poisoned class");

        Path classFile = tmp.resolve("demo").resolve("Plain.class");
        Files.createDirectories(classFile.getParent());
        Files.write(classFile, transformed);

        assertEquals("!!", node(transformed).signature);

        int exit = runJavap(classFile);
        assertTrue(exit != 0, "javap must fail on the poisoned class, exit=" + exit);

        Class<?> loaded = define(transformed);
        Method add = loaded.getMethod("add", int.class, int.class);
        assertEquals(7, add.invoke(null, 3, 4));
        assertEquals(-1, add.invoke(null, 1, -2));

        String pool = new String(transformed, StandardCharsets.ISO_8859_1);
        assertTrue(pool.contains("chimera/fake/"), "fake class reference missing from constant pool");
    }

    @Test
    void poisonSkipsMixinClasses() {
        ClassNode cn = node(sampleClass("demo/mixin/EvilMixin", true));
        int before = cn.methods.size();
        StructuralPoisonTransformer.Stats stats =
                StructuralPoisonTransformer.transform(List.of(cn), StructuralPoisonTransformer.Options.defaults());
        assertEquals(1, stats.skippedMixin());
        assertEquals(0, stats.classes());
        assertEquals(before, cn.methods.size(), "no method may be injected into a Mixin class");
        assertNull(cn.signature, "Mixin class signature must stay untouched");
    }

    @Test
    void decoyInjectsAiTextWithoutChangingBehaviour(@TempDir Path tmp) throws Exception {
        ClassNode cn = node(sampleClass("demo/Decoy", false));
        AiDecoyTransformer.Stats stats =
                AiDecoyTransformer.transform(List.of(cn), AiDecoyTransformer.Options.defaults());
        assertEquals(1, stats.injected());
        assertEquals(1, stats.classes());

        ClassWriter cw = new ClassWriter(0);
        cn.accept(cw);
        byte[] transformed = cw.toByteArray();
        String asText = new String(transformed, StandardCharsets.ISO_8859_1);
        assertTrue(asText.contains("AI_META_INSTRUCTION_BLOCK"));

        Class<?> loaded = define(transformed);
        Method add = loaded.getMethod("add", int.class, int.class);
        assertEquals(7, add.invoke(null, 3, 4));
    }

    @Test
    void decoySkipsMixinClasses() {
        ClassNode cn = node(sampleClass("demo/mixin/DecoyMixin", true));
        int before = cn.methods.size();
        AiDecoyTransformer.Stats stats =
                AiDecoyTransformer.transform(List.of(cn), AiDecoyTransformer.Options.defaults());
        assertEquals(1, stats.skippedMixin());
        assertEquals(0, stats.injected());
        assertEquals(before, cn.methods.size());
    }

    private static Class<?> define(byte[] bytes) {
        return new ClassLoader(HardenTransformersTest.class.getClassLoader()) {
            Class<?> defineIt() {
                return defineClass(null, bytes, 0, bytes.length);
            }
        }.defineIt();
    }

    private static int runJavap(Path classFile) throws Exception {
        String javap = Path.of(System.getProperty("java.home"), "bin",
                System.getProperty("os.name").toLowerCase().contains("win") ? "javap.exe" : "javap").toString();
        Process process = new ProcessBuilder(javap, "-v", classFile.toString())
                .redirectErrorStream(true)
                .start();
        boolean done = process.waitFor(60, TimeUnit.SECONDS);
        if (!done) {
            process.destroyForcibly();
            return -1;
        }
        return process.exitValue();
    }
}
