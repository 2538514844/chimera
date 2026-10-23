package dev.chimera.transform;

import dev.chimera.core.ChimeraConfig;
import dev.chimera.core.ChimeraEngine;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.Label;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;

/** M7/Module 4: @ChimeraPreGameCheck is enforced automatically at build time. */
class PreGameCheckTransformerTest {

    private static final String PREGAME = "Ldev/chimera/annotations/ChimeraPreGameCheck;";

    private static ChimeraConfig config(Path in, Path out) {
        ChimeraConfig cfg = new ChimeraConfig();
        cfg.inputJar = in;
        cfg.outputJar = out;
        cfg.keyMaterial = new byte[32];
        cfg.rename = false;
        cfg.encryptStrings = false;
        cfg.fragmentMethods = false;
        cfg.nativeStubs = false;
        cfg.entangle = false;
        cfg.honeypot = false;
        cfg.vm = false;
        cfg.integrityManifest = false;
        return cfg;
    }

    private static void annotate(MethodVisitor visitor) {
        AnnotationVisitor annotation = visitor.visitAnnotation(PREGAME, true);
        annotation.visitEnd();
    }

    private static byte[] guarded() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL,
                "fixtures/pregame/Guarded", null, "java/lang/Object", null);
        MethodVisitor enter = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "enter", "()I", null, null);
        annotate(enter);
        enter.visitCode();
        enter.visitIntInsn(Opcodes.BIPUSH, 42);
        enter.visitInsn(Opcodes.IRETURN);
        enter.visitMaxs(1, 0);
        enter.visitEnd();
        MethodVisitor enterVoid = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "enterVoid", "()V", null, null);
        annotate(enterVoid);
        enterVoid.visitCode();
        enterVoid.visitInsn(Opcodes.RETURN);
        enterVoid.visitMaxs(0, 0);
        enterVoid.visitEnd();

        MethodVisitor enterLong = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "enterLong", "()J", null, null);
        annotate(enterLong);
        enterLong.visitCode();
        enterLong.visitInsn(Opcodes.LCONST_1);
        enterLong.visitInsn(Opcodes.LRETURN);
        enterLong.visitMaxs(2, 0);
        enterLong.visitEnd();

        MethodVisitor enterDouble = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "enterDouble", "()D", null, null);
        annotate(enterDouble);
        enterDouble.visitCode();
        enterDouble.visitInsn(Opcodes.DCONST_1);
        enterDouble.visitInsn(Opcodes.DRETURN);
        enterDouble.visitMaxs(2, 0);
        enterDouble.visitEnd();

        MethodVisitor enterFloat = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "enterFloat", "()F", null, null);
        annotate(enterFloat);
        enterFloat.visitCode();
        enterFloat.visitInsn(Opcodes.FCONST_1);
        enterFloat.visitInsn(Opcodes.FRETURN);
        enterFloat.visitMaxs(1, 0);
        enterFloat.visitEnd();

        MethodVisitor enterObject = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "enterObject", "()Ljava/lang/Object;", null, null);
        annotate(enterObject);
        enterObject.visitCode();
        enterObject.visitInsn(Opcodes.ACONST_NULL);
        enterObject.visitInsn(Opcodes.ARETURN);
        enterObject.visitMaxs(1, 0);
        enterObject.visitEnd();

        MethodVisitor enterBoolean = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "enterBoolean", "()Z", null, null);
        annotate(enterBoolean);
        enterBoolean.visitCode();
        enterBoolean.visitInsn(Opcodes.ICONST_1);
        enterBoolean.visitInsn(Opcodes.IRETURN);
        enterBoolean.visitMaxs(1, 0);
        enterBoolean.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] booleanBranchUser() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL,
                "fixtures/pregame/BoolUser", null, "java/lang/Object", null);
        MethodVisitor use = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "use", "()I", null, null);
        use.visitCode();
        use.visitMethodInsn(Opcodes.INVOKESTATIC, "fixtures/pregame/Guarded",
                "enterBoolean", "()Z", false);
        Label skip = new Label();
        use.visitJumpInsn(Opcodes.IFEQ, skip);
        use.visitIntInsn(Opcodes.BIPUSH, 1);
        use.visitInsn(Opcodes.IRETURN);
        use.visitLabel(skip);
        use.visitInsn(Opcodes.ICONST_0);
        use.visitInsn(Opcodes.IRETURN);
        use.visitMaxs(1, 0);
        use.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] constructorAnnotated() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixtures/pregame/BadCtor",
                null, "java/lang/Object", null);
        MethodVisitor init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        annotate(init);
        init.visitCode();
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(1, 1);
        init.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] abstractAnnotated() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT,
                "fixtures/pregame/BadAbstract", null, "java/lang/Object", null);
        MethodVisitor method = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT,
                "enter", "()I", null, null);
        annotate(method);
        method.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static Path buildJar(Path work, Map<String, byte[]> classes) throws Exception {
        Path jar = work.resolve("pregame-in.jar");
        Files.createDirectories(work);
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(jar))) {
            for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
                zos.putNextEntry(new ZipEntry(entry.getKey()));
                zos.write(entry.getValue());
                zos.closeEntry();
            }
        }
        return jar;
    }

    @Test
    void injectsPreGameCheckPrologueAndReturnsDefaultOnFailure() throws Exception {
        Path work = Files.createTempDirectory("chimera-pregame");
        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put("fixtures/pregame/Guarded.class", guarded());
        Path in = buildJar(work, classes);
        Path out = work.resolve("pregame-out.jar");
        new ChimeraEngine(config(in, out)).run();

        Map<String, byte[]> entries = readJar(out);
        byte[] bytes = entries.get("fixtures/pregame/Guarded.class");
        assertNotNull(bytes, "class must be present");
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        MethodNode enter = node.methods.stream()
                .filter(m -> m.name.equals("enter")).findFirst().orElseThrow();
        AbstractInsnNode first = enter.instructions.getFirst();
        assertTrue(first instanceof MethodInsnNode call0
                        && call0.getOpcode() == Opcodes.INVOKESTATIC
                        && call0.owner.equals("dev/chimera/runtime/ChimeraRuntime"),
                "prologue must start with the runtime check");
        boolean callFound = false;
        for (var insn : enter.instructions) {
            if (insn instanceof MethodInsnNode call
                    && call.getOpcode() == Opcodes.INVOKESTATIC
                    && call.owner.equals("dev/chimera/runtime/ChimeraRuntime")
                    && (call.name.equals("preGameCheckFromProperties")
                    || call.name.equals("preGameCheckWithFallback"))) {
                callFound = true;
                break;
            }
        }
        assertTrue(callFound, "pre-game check must be injected");

        try (URLClassLoader loader = new URLClassLoader(new URL[]{out.toUri().toURL()},
                ClassLoader.getPlatformClassLoader())) {
            Class<?> guardedClass = Class.forName("fixtures.pregame.Guarded", true, loader);
            // A3: no 0/0L/0.0 sentinel; every non-void type must match the M2 poison shape.
            assertEquals(Integer.MIN_VALUE, guardedClass.getMethod("enter").invoke(null),
                    "int failure must be the M2 negative poison, not 0");
            assertEquals(Long.MIN_VALUE, guardedClass.getMethod("enterLong").invoke(null),
                    "long failure must flip the sign bit, not 0L");
            Object doubleResult = guardedClass.getMethod("enterDouble").invoke(null);
            assertTrue(Double.isNaN(((Double) doubleResult).doubleValue()),
                    "double failure must be NaN");
            Object floatResult = guardedClass.getMethod("enterFloat").invoke(null);
            assertTrue(Float.isNaN(((Float) floatResult).floatValue()),
                    "float failure must be NaN");
            assertNull(guardedClass.getMethod("enterObject").invoke(null),
                    "reference failure is null (documented residual distinguishability)");
            assertEquals(Boolean.FALSE, guardedClass.getMethod("enterBoolean").invoke(null),
                    "boolean failure must stay false, never a truthy poison");
            guardedClass.getMethod("enterVoid").invoke(null);
            Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true, loader);
            assertEquals(Boolean.FALSE, runtime.getMethod("isKeyHealthy").invoke(null),
                    "failed pre-game check must poison the runtime");
            // Verifier-level regression: each type is invoked above; a bad stack/frame shape would
            // surface as VerifyError at first invocation, not as an assertion failure.
        }
    }

    @Test
    void injectionDoesNotDependOnEncryptedStrings() throws Exception {
        // Regression: the prologue used to be injected before string encryption, so the empty
        // annotation values became decryptStr(id) calls that poisoned the runtime before the
        // content key existed (breaking a valid first activation).
        Path work = Files.createTempDirectory("chimera-pregame-order");
        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put("fixtures/pregame/Guarded.class", guarded());
        Path in = buildJar(work, classes);
        Path out = work.resolve("pregame-strings.jar");
        ChimeraConfig cfg = config(in, out);
        cfg.encryptStrings = true;
        new ChimeraEngine(cfg).run();

        Map<String, byte[]> entries = readJar(out);
        ClassNode node = new ClassNode();
        new ClassReader(entries.get("fixtures/pregame/Guarded.class")).accept(node, 0);
        MethodNode enter = node.methods.stream()
                .filter(m -> m.name.equals("enter")).findFirst().orElseThrow();
        AbstractInsnNode first = enter.instructions.getFirst();
        assertTrue(first instanceof MethodInsnNode call
                        && call.owner.equals("dev/chimera/runtime/ChimeraRuntime")
                        && call.name.equals("preGameCheckFromProperties"),
                "prologue must call the no-argument property checker, not a string id");
        AbstractInsnNode second = first.getNext();
        assertFalse(second instanceof LdcInsnNode,
                "no encrypted string constant may precede the pre-game check");
    }

    @Test
    void rejectsBooleanPgcReturnUsedAsSecurityBranch() throws Exception {
        Path work = Files.createTempDirectory("chimera-pregame-bool");
        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put("fixtures/pregame/Guarded.class", guarded());
        classes.put("fixtures/pregame/BoolUser.class", booleanBranchUser());
        Path in = buildJar(work, classes);
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> new ChimeraEngine(config(in, work.resolve("out.jar"))).run());
        assertTrue(error.getMessage().contains("boolean PGC audit failed"), error.getMessage());
        assertTrue(error.getMessage().contains("BoolUser.use"), error.getMessage());
    }

    @Test
    void rejectsAnnotationOnConstructor() throws Exception {
        Path work = Files.createTempDirectory("chimera-pregame-ctor");
        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put("fixtures/pregame/BadCtor.class", constructorAnnotated());
        Path in = buildJar(work, classes);
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> new ChimeraEngine(config(in, work.resolve("out.jar"))).run());
        assertTrue(error.getMessage().contains("constructor"), error.getMessage());
    }

    @Test
    void rejectsAnnotationOnAbstractMethod() throws Exception {
        Path work = Files.createTempDirectory("chimera-pregame-abstract");
        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put("fixtures/pregame/BadAbstract.class", abstractAnnotated());
        Path in = buildJar(work, classes);
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> new ChimeraEngine(config(in, work.resolve("out.jar"))).run());
        assertTrue(error.getMessage().contains("abstract"), error.getMessage());
    }

    private static Map<String, byte[]> readJar(Path jar) throws Exception {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        try (var zip = new java.util.zip.ZipFile(jar.toFile())) {
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
