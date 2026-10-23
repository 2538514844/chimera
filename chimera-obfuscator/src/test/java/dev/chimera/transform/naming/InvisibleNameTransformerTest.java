package dev.chimera.transform.naming;

import org.junit.jupiter.api.Test;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.*;

/** M13: invisible naming pre-pass (Hachimi parity). */
class InvisibleNameTransformerTest {

    private static final int API = Opcodes.ASM9;
    private static final String TEST_PKG = "example/";

    // ------------------------------------------------------------------
    // ASM helpers: build small self-contained classes without javac fixtures
    // ------------------------------------------------------------------

    private static byte[] makeClass(String name, int access, String superName, String[] interfaces,
                                    Consumer<ClassWriter> body) {
        return makeClass(name, access, superName, null, interfaces, body);
    }

    private static byte[] makeClass(String name, int access, String superName, String signature,
                                    String[] interfaces, Consumer<ClassWriter> body) {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, access, name, signature, superName, interfaces);
        body.accept(cw);
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static void defaultConstructor(ClassWriter cw, String superName) {
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, superName, "<init>", "()V", false);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(1, 1);
        mv.visitEnd();
    }

    private static byte[] calcClass() {
        return makeClass(TEST_PKG + "Calc", Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER,
                "java/lang/Object", null, cw -> {
                    cw.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                            "BASE", "I", null, 10).visitEnd();
                    defaultConstructor(cw, "java/lang/Object");
                    MethodVisitor add = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                            "add", "(II)I", null, null);
                    add.visitCode();
                    add.visitVarInsn(Opcodes.ILOAD, 0);
                    add.visitVarInsn(Opcodes.ILOAD, 1);
                    add.visitInsn(Opcodes.IADD);
                    add.visitInsn(Opcodes.IRETURN);
                    add.visitMaxs(2, 2);
                    add.visitEnd();
                    MethodVisitor mul = cw.visitMethod(Opcodes.ACC_PUBLIC, "mul", "(II)I", null, null);
                    mul.visitCode();
                    mul.visitVarInsn(Opcodes.ILOAD, 1);
                    mul.visitVarInsn(Opcodes.ILOAD, 2);
                    mul.visitInsn(Opcodes.IMUL);
                    mul.visitInsn(Opcodes.IRETURN);
                    mul.visitMaxs(2, 3);
                    mul.visitEnd();
                });
    }

    private static byte[] useClass() {
        return makeClass(TEST_PKG + "Use", Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "java/lang/Object", null, cw -> {
                    defaultConstructor(cw, "java/lang/Object");
                    MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                            "compute", "()I", null, null);
                    mv.visitCode();
                    mv.visitFieldInsn(Opcodes.GETSTATIC, TEST_PKG + "Calc", "BASE", "I");
                    mv.visitIntInsn(Opcodes.BIPUSH, 32);
                    mv.visitMethodInsn(Opcodes.INVOKESTATIC, TEST_PKG + "Calc", "add", "(II)I", false);
                    mv.visitTypeInsn(Opcodes.NEW, TEST_PKG + "Calc");
                    mv.visitInsn(Opcodes.DUP);
                    mv.visitMethodInsn(Opcodes.INVOKESPECIAL, TEST_PKG + "Calc", "<init>", "()V", false);
                    mv.visitInsn(Opcodes.ICONST_3);
                    mv.visitInsn(Opcodes.ICONST_4);
                    mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, TEST_PKG + "Calc", "mul", "(II)I", false);
                    mv.visitInsn(Opcodes.IADD);
                    mv.visitInsn(Opcodes.IRETURN);
                    mv.visitMaxs(4, 1);
                    mv.visitEnd();
                    // Constant-pool strings that must be synchronised (reflection paths).
                    MethodVisitor strings = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                            "strings", "()[Ljava/lang/String;", null, null);
                    strings.visitCode();
                    strings.visitInsn(Opcodes.ICONST_3);
                    strings.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/String");
                    strings.visitInsn(Opcodes.DUP);
                    strings.visitInsn(Opcodes.ICONST_0);
                    strings.visitLdcInsn(TEST_PKG + "Calc");
                    strings.visitInsn(Opcodes.AASTORE);
                    strings.visitInsn(Opcodes.DUP);
                    strings.visitInsn(Opcodes.ICONST_1);
                    strings.visitLdcInsn("example.Calc");
                    strings.visitInsn(Opcodes.AASTORE);
                    strings.visitInsn(Opcodes.DUP);
                    strings.visitInsn(Opcodes.ICONST_2);
                    strings.visitLdcInsn("prefix " + TEST_PKG + "Calc suffix");
                    strings.visitInsn(Opcodes.AASTORE);
                    strings.visitInsn(Opcodes.ARETURN);
                    strings.visitMaxs(4, 0);
                    strings.visitEnd();
                });
    }

    private static Map<String, byte[]> baseClasses() {
        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put(TEST_PKG + "Calc.class", calcClass());
        classes.put(TEST_PKG + "Use.class", useClass());
        return classes;
    }

    private static Map<String, byte[]> baseResources() {
        Map<String, byte[]> resources = new LinkedHashMap<>();
        resources.put("fabric.mod.json",
                "{\"schemaVersion\":1,\"id\":\"fixture\",\"version\":\"1.0.0\",\"entrypoints\":{\"main\":[\"example.Use\"]}}"
                        .getBytes(StandardCharsets.UTF_8));
        resources.put("mixins.json",
                "{\"required\":true,\"package\":\"example.mixin\",\"mixins\":[\"example.ProtectedByConfig\"],"
                        .concat("\"refmap\":\"example.refmap.json\"}")
                        .getBytes(StandardCharsets.UTF_8));
        resources.put("example.refmap.json",
                "{\"mappings\":{\"example/MixinThing\":{\"field\":\"a\"}}}".getBytes(StandardCharsets.UTF_8));
        resources.put("example/Calc.json",
                "{\"class\":\"example/Calc\",\"internal\":\"example/Calc\"}".getBytes(StandardCharsets.UTF_8));
        resources.put("META-INF/services/example.Service",
                "example.Use\n".getBytes(StandardCharsets.UTF_8));
        return resources;
    }

    // ------------------------------------------------------------------
    // Loader helper
    // ------------------------------------------------------------------

    private static final class MapClassLoader extends ClassLoader {
        private final Map<String, byte[]> classes;

        private MapClassLoader(Map<String, byte[]> classes) {
            super(InvisibleNameTransformerTest.class.getClassLoader());
            this.classes = classes;
        }

        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            byte[] bytes = classes.get(name.replace('.', '/'));
            if (bytes == null) {
                throw new ClassNotFoundException(name);
            }
            return defineClass(name, bytes, 0, bytes.length);
        }
    }

    private static String renamedInternal(Map<String, byte[]> classes, String original) {
        String packagePrefix = InvisibleNames.packagePrefix(original);
        String simple = InvisibleNames.simpleName(original);
        for (String key : classes.keySet()) {
            String internal = key.substring(0, key.length() - ".class".length());
            if (!internal.startsWith(packagePrefix)) {
                continue;
            }
            String remainder = internal.substring(packagePrefix.length())
                    .replace(String.valueOf(InvisibleNames.NUL), "");
            if (remainder.startsWith(simple)) {
                return internal;
            }
        }
        fail("renamed class not found for " + original);
        return null;
    }

    private static ClassNode parse(byte[] bytes) {
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return node;
    }

    private static List<String> stringConstants(ClassNode node) {
        List<String> values = new ArrayList<>();
        for (MethodNode method : node.methods) {
            if (method.instructions == null) {
                continue;
            }
            for (var insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof org.objectweb.asm.tree.LdcInsnNode ldc && ldc.cst instanceof String s) {
                    values.add(s);
                }
            }
        }
        return values;
    }

    // ------------------------------------------------------------------
    // Tests
    // ------------------------------------------------------------------

    @Test
    void renamesClassesAndMembersWithInvisibleSuffix() {
        Map<String, byte[]> classes = baseClasses();
        InvisibleNameTransformer.Result result =
                InvisibleNameTransformer.apply(classes, Map.of(), InvisibleNameTransformer.Options.defaults());

        // example.Calc is named by string constants inside example.Use (the Class.forName paths), so
        // the reflection rule keeps that class name; example.Use itself is free to rename.
        assertEquals(1, result.classesRenamed(), "only the unreferenced class is renamed");
        assertTrue(result.classes().containsKey(TEST_PKG + "Calc.class"),
                "class named by a string constant keeps its name; keys=" + result.classes().keySet());
        assertTrue(result.membersRenamed() > 0, "members are renamed");

        String use = renamedInternal(result.classes(), TEST_PKG + "Use");
        assertTrue(use.startsWith(TEST_PKG + "Use"), "original simple name is kept as prefix: " + use);
        assertTrue(InvisibleNames.containsInvisible(use), "class name carries invisible suffix");

        ClassNode useNode = parse(result.classes().get(use + ".class"));
        boolean computeRenamed = false;
        for (MethodNode method : useNode.methods) {
            if ("<init>".equals(method.name)) {
                assertEquals("<init>", method.name, "constructors are never renamed");
            } else {
                assertTrue(InvisibleNames.containsInvisible(method.name),
                        "method name carries invisible suffix: " + method.name);
                assertTrue(method.name.startsWith("compute") || method.name.startsWith("strings"),
                        "renamed method keeps its original prefix: " + method.name);
                computeRenamed |= method.name.startsWith("compute");
            }
        }
        assertTrue(computeRenamed, "compute() must be renamed in place");
        ClassNode calcNode = parse(result.classes().get(TEST_PKG + "Calc.class"));
        assertEquals(TEST_PKG + "Calc", calcNode.name, "kept class name");
        assertTrue(calcNode.fields.stream().anyMatch(
                        f -> f.name.startsWith("BASE") && InvisibleNames.containsInvisible(f.name)),
                "members of a kept class are still renamed in place");
    }

    @Test
    void transformedClassesParseWithAsmAndStillRun() throws Exception {
        InvisibleNameTransformer.Result result =
                InvisibleNameTransformer.apply(baseClasses(), baseResources(),
                        InvisibleNameTransformer.Options.defaults());

        Map<String, byte[]> byInternal = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> entry : result.classes().entrySet()) {
            byInternal.put(entry.getKey().substring(0, entry.getKey().length() - ".class".length()),
                    entry.getValue());
        }
        // ASM must still parse every emitted class.
        for (Map.Entry<String, byte[]> entry : byInternal.entrySet()) {
            ClassNode node = parse(entry.getValue());
            assertEquals(entry.getKey(), node.name, "class name and map key agree");
        }

        MapClassLoader loader = new MapClassLoader(byInternal);
        Class<?> use = Class.forName(renamedInternal(result.classes(), TEST_PKG + "Use").replace('/', '.'),
                true, loader);
        Method compute = Arrays.stream(use.getDeclaredMethods())
                .filter(m -> Modifier.isStatic(m.getModifiers()) && m.getParameterCount() == 0
                        && m.getReturnType() == int.class)
                .findFirst().orElseThrow();
        compute.setAccessible(true);
        assertEquals(10 + 32 + 3 * 4, compute.invoke(null), "behaviour is preserved after renaming");

        Class<?> calc = Class.forName(renamedInternal(result.classes(), TEST_PKG + "Calc").replace('/', '.'),
                true, loader);
        Object instance = calc.getDeclaredConstructor().newInstance();
        Method mul = Arrays.stream(calc.getDeclaredMethods())
                .filter(m -> !Modifier.isStatic(m.getModifiers()) && m.getParameterCount() == 2
                        && m.getReturnType() == int.class)
                .findFirst().orElseThrow();
        mul.setAccessible(true);
        assertEquals(12, mul.invoke(instance, 3, 4), "virtual dispatch (final class) still works");
    }

    @Test
    void constantPoolStringsAndResourcesAreSynchronised() {
        InvisibleNameTransformer.Result result =
                InvisibleNameTransformer.apply(baseClasses(), baseResources(),
                        InvisibleNameTransformer.Options.defaults());
        String calcInternal = renamedInternal(result.classes(), TEST_PKG + "Calc");
        String useInternal = renamedInternal(result.classes(), TEST_PKG + "Use");
        String calcBinary = InvisibleNames.binaryName(calcInternal);
        String useBinary = InvisibleNames.binaryName(useInternal);

        ClassNode useNode = parse(result.classes().get(useInternal + ".class"));
        List<String> strings = stringConstants(useNode);
        assertTrue(strings.contains(calcInternal), "internal-name string updated: " + strings);
        assertTrue(strings.contains(calcBinary), "binary-name string updated: " + strings);
        assertTrue(strings.stream().anyMatch(s -> s.contains(calcInternal) && s.startsWith("prefix ")),
                "token inside a longer string updated: " + strings);

        String fabric = new String(result.resources().get("fabric.mod.json"), StandardCharsets.UTF_8);
        assertTrue(fabric.contains(useBinary), "fabric.mod.json entrypoint synchronised");
        assertFalse(fabric.contains("\"example.Use\""), "old entrypoint name is gone");

        // example.Calc keeps its name (string constants in Use name it), so its resource keeps its
        // path and body: a resource path only follows an actual class rename.
        assertTrue(result.resources().containsKey("example/Calc.json"),
                "resource of a kept class stays under its path: " + result.resources().keySet());
        String json = new String(result.resources().get("example/Calc.json"), StandardCharsets.UTF_8);
        assertTrue(json.contains(calcInternal), "kept resource body still points at the class: " + json);

        String service = new String(result.resources().get("META-INF/services/example.Service"),
                StandardCharsets.UTF_8);
        assertFalse(service.contains("example.Use\n"), "service file old entry gone: " + service);
        assertTrue(service.contains(useBinary), "service file body now points at the renamed class: " + service);
        // Nothing that was renamed is also named by a string constant (Use has no self-reference),
        // so there is no string to rewrite; the kept names above must be intact.
        assertEquals(0, result.stringsSynced(), "no class-name string had to be rewritten");
        assertTrue(result.resourcesSynced() > 0, "entrypoint/service resources were rewritten");
    }

    @Test
    void mixinEnumRecordAnnotationAndNativeOwnersAreByteIdentical() {
        byte[] mixin = makeClass(TEST_PKG + "MixinThing",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, "java/lang/Object", "Ljava/lang/Object;",
                null, cw -> {
                    cw.visitSource("MixinThing.java", null);
                    AnnotationVisitor annotation = cw.visitAnnotation(
                            "Lorg/spongepowered/asm/mixin/Mixin;", true);
                    annotation.visitEnd();
                    defaultConstructor(cw, "java/lang/Object");
                    MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "injected", "()V", null, null);
                    mv.visitCode();
                    org.objectweb.asm.Label label = new org.objectweb.asm.Label();
                    mv.visitLabel(label);
                    mv.visitLineNumber(7, label);
                    mv.visitInsn(Opcodes.RETURN);
                    mv.visitMaxs(0, 1);
                    mv.visitEnd();
                });
        byte[] protectedByConfig = makeClass(TEST_PKG + "ProtectedByConfig",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, "java/lang/Object", null,
                cw -> defaultConstructor(cw, "java/lang/Object"));
        byte[] enumClass = makeClass(TEST_PKG + "PlainEnum",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_ENUM | Opcodes.ACC_SUPER,
                "java/lang/Enum", null, cw -> {
                    cw.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL
                            | Opcodes.ACC_ENUM, "A", "L" + TEST_PKG + "PlainEnum;", null, null).visitEnd();
                });
        byte[] recordClass = makeClass(TEST_PKG + "PlainRecord",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_RECORD | Opcodes.ACC_SUPER,
                "java/lang/Record", null, cw -> {
                    cw.visitRecordComponent("x", "I", null).visitEnd();
                    cw.visitField(Opcodes.ACC_PRIVATE | Opcodes.ACC_FINAL, "x", "I", null, null).visitEnd();
                });
        byte[] annotationClass = makeClass(TEST_PKG + "PlainAnnotation",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_ANNOTATION | Opcodes.ACC_INTERFACE
                        | Opcodes.ACC_ABSTRACT, "java/lang/Object",
                new String[]{"java/lang/annotation/Annotation"}, cw -> {
                    MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT,
                            "value", "()I", null, null);
                    mv.visitEnd();
                });
        byte[] nativeOwner = makeClass(TEST_PKG + "NativeOwner",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, "java/lang/Object", null, cw -> {
                    defaultConstructor(cw, "java/lang/Object");
                    MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                            "nativeWork", "(I)I", null, null);
                    AnnotationVisitor av = mv.visitAnnotation(
                            "Ldev/chimera/annotations/ChimeraNative;", true);
                    av.visitEnd();
                    mv.visitCode();
                    mv.visitVarInsn(Opcodes.ILOAD, 0);
                    mv.visitInsn(Opcodes.IRETURN);
                    mv.visitMaxs(1, 1);
                    mv.visitEnd();
                });
        byte[] plainInterface = makeClass(TEST_PKG + "PlainInterface",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT,
                "java/lang/Object", null, cw -> cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT,
                "run", "()V", null, null).visitEnd());

        Map<String, byte[]> classes = baseClasses();
        classes.put(TEST_PKG + "MixinThing.class", mixin);
        classes.put(TEST_PKG + "ProtectedByConfig.class", protectedByConfig);
        classes.put(TEST_PKG + "PlainEnum.class", enumClass);
        classes.put(TEST_PKG + "PlainRecord.class", recordClass);
        classes.put(TEST_PKG + "PlainAnnotation.class", annotationClass);
        classes.put(TEST_PKG + "NativeOwner.class", nativeOwner);
        classes.put(TEST_PKG + "PlainInterface.class", plainInterface);

        InvisibleNameTransformer.Result result = InvisibleNameTransformer.apply(classes, baseResources(),
                InvisibleNameTransformer.Options.defaults());

        assertSameBytes(mixin, result.classes().get(TEST_PKG + "MixinThing.class"), "Mixin class");
        assertSameBytes(protectedByConfig, result.classes().get(TEST_PKG + "ProtectedByConfig.class"),
                "class listed in mixins.json");
        assertSameBytes(enumClass, result.classes().get(TEST_PKG + "PlainEnum.class"), "enum");
        assertSameBytes(recordClass, result.classes().get(TEST_PKG + "PlainRecord.class"), "record");
        assertSameBytes(annotationClass, result.classes().get(TEST_PKG + "PlainAnnotation.class"),
                "annotation type");
        assertSameBytes(nativeOwner, result.classes().get(TEST_PKG + "NativeOwner.class"),
                "@ChimeraNative owner");
        assertSameBytes(plainInterface, result.classes().get(TEST_PKG + "PlainInterface.class"),
                "interface (default: not renamed)");

        // Mixin config/refmap must stay byte-identical as well.
        assertArrayEquals("{\"required\":true,\"package\":\"example.mixin\",\"mixins\":"
                        .concat("[\"example.ProtectedByConfig\"],\"refmap\":\"example.refmap.json\"}")
                        .getBytes(StandardCharsets.UTF_8),
                result.resources().get("mixins.json"), "mixin config unchanged");
        assertArrayEquals("{\"mappings\":{\"example/MixinThing\":{\"field\":\"a\"}}}"
                        .getBytes(StandardCharsets.UTF_8),
                result.resources().get("example.refmap.json"), "refmap unchanged");
    }

    private static void assertSameBytes(byte[] expected, byte[] actual, String what) {
        assertNotNull(actual, what + " missing");
        assertArrayEquals(expected, actual, what + " modified");
    }

    @Test
    void memberNamesAreUniqueAndUseAllThreeCodePoints() {
        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put(TEST_PKG + "Many.class", makeClass(TEST_PKG + "Many",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER, "java/lang/Object", null, cw -> {
                    defaultConstructor(cw, "java/lang/Object");
                    for (int i = 0; i < 12; i++) {
                        cw.visitField(Opcodes.ACC_PUBLIC, "f" + i, "I", null, null).visitEnd();
                        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                                "m" + i, "()I", null, null);
                        mv.visitCode();
                        mv.visitIntInsn(Opcodes.BIPUSH, i);
                        mv.visitInsn(Opcodes.IRETURN);
                        mv.visitMaxs(1, 0);
                        mv.visitEnd();
                    }
                }));
        InvisibleNameTransformer.Result result = InvisibleNameTransformer.apply(classes, Map.of(),
                InvisibleNameTransformer.Options.defaults());
        String internal = renamedInternal(result.classes(), TEST_PKG + "Many");
        ClassNode node = parse(result.classes().get(internal + ".class"));

        Set<String> methodNames = new LinkedHashSet<>();
        Set<Character> codePoints = new HashSet<>();
        for (MethodNode method : node.methods) {
            if ("<init>".equals(method.name)) {
                continue;
            }
            methodNames.add(method.name);
            for (int i = 0; i < method.name.length(); i++) {
                if (InvisibleNames.TARGET_CODE_POINTS.contains(method.name.charAt(i))) {
                    codePoints.add(method.name.charAt(i));
                }
            }
        }
        assertEquals(12, methodNames.size(), "renamed method names are unique");
        assertEquals(InvisibleNames.TARGET_CODE_POINTS, codePoints,
                "suffixes combine all three invisible code points");
        Set<String> fieldNames = new LinkedHashSet<>();
        for (FieldNode field : node.fields) {
            fieldNames.add(field.name);
            assertTrue(InvisibleNames.containsInvisible(field.name));
        }
        assertEquals(12, fieldNames.size(), "renamed field names are unique");
    }

    @Test
    void nulPrefixOptionIsIgnoredAndNamesStayJsonSafe() throws Exception {
        InvisibleNameTransformer.Options options = InvisibleNameTransformer.Options.defaults();
        options.nulPrefix = true;
        InvisibleNameTransformer.Result result =
                InvisibleNameTransformer.apply(baseClasses(), baseResources(), options);
        // S1 redesign: a jar entry must be stored under the class's real internal name, so the
        // NUL-prefix experiment was dropped. The option is still accepted (source compatibility)
        // but it must never put a NUL back into a name: NUL breaks jar entry lookup and JSON.
        // example.Use is the class that actually gets renamed; example.Calc is kept (its name is a
        // string constant), so the NUL prefix can only ever appear on a renamed name.
        String useInternal = renamedInternal(result.classes(), TEST_PKG + "Use");
        assertTrue(useInternal.contains(String.valueOf(InvisibleNames.NUL)),
                "NUL prefix enabled for the renamed class: "
                        + useInternal.replace("\0", "<NUL>"));

        String fabric = new String(result.resources().get("fabric.mod.json"), StandardCharsets.UTF_8);
        assertTrue(fabric.contains("\\u0000"), "JSON escapes NUL: " + fabric);
        for (byte b : fabric.getBytes(StandardCharsets.UTF_8)) {
            assertNotEquals(0, Byte.toUnsignedInt(b), "no raw NUL byte in JSON");
        }

        Map<String, byte[]> byInternal = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> entry : result.classes().entrySet()) {
            byInternal.put(entry.getKey().substring(0, entry.getKey().length() - ".class".length()),
                    entry.getValue());
        }
        MapClassLoader loader = new MapClassLoader(byInternal);
        Class<?> use = Class.forName(renamedInternal(result.classes(), TEST_PKG + "Use").replace('/', '.'),
                true, loader);
        Method compute = Arrays.stream(use.getDeclaredMethods())
                .filter(m -> Modifier.isStatic(m.getModifiers()) && m.getParameterCount() == 0
                        && m.getReturnType() == int.class)
                .findFirst().orElseThrow();
        compute.setAccessible(true);
        assertEquals(54, compute.invoke(null), "NUL-prefixed classes still load and execute");
    }

    @Test
    void reRunningOnRenamedOutputIsIdempotent() {
        InvisibleNameTransformer.Result first = InvisibleNameTransformer.apply(baseClasses(), baseResources(),
                InvisibleNameTransformer.Options.defaults());
        InvisibleNameTransformer.Result second = InvisibleNameTransformer.apply(first.classes(),
                first.resources(), InvisibleNameTransformer.Options.defaults());
        assertEquals(0, second.classesRenamed(), "already-renamed classes are not renamed twice");
        assertEquals(0, second.membersRenamed(), "already-renamed members are not renamed twice");
        assertEquals(first.classes().keySet(), second.classes().keySet());
    }

    // ------------------------------------------------------------------
    // Frozen reference graph (production crash prevention)
    // ------------------------------------------------------------------

    private static void addMixinTargets(ClassWriter cw, String... targets) {
        AnnotationVisitor mixin = cw.visitAnnotation("Lorg/spongepowered/asm/mixin/Mixin;", true);
        AnnotationVisitor array = mixin.visitArray("targets");
        for (String target : targets) {
            array.visit(null, target);
        }
        array.visitEnd();
        mixin.visitEnd();
    }

    private static byte[] eventClass() {
        return makeClass(TEST_PKG + "Event",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER, "java/lang/Object", null, cw -> {
                    cw.visitField(Opcodes.ACC_PUBLIC, "value", "I", null, null).visitEnd();
                    defaultConstructor(cw, "java/lang/Object");
                    for (String name : new String[]{"helper", "other"}) {
                        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, name, "()I", null, null);
                        mv.visitCode();
                        mv.visitIntInsn(Opcodes.BIPUSH, name.equals("helper") ? 7 : 9);
                        mv.visitInsn(Opcodes.IRETURN);
                        mv.visitMaxs(1, 1);
                        mv.visitEnd();
                    }
                });
    }

    private static byte[] mixinReferencingEvent() {
        return makeClass(TEST_PKG + "MixinThing",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, "java/lang/Object", null, cw -> {
                    addMixinTargets(cw, "example.Event");
                    cw.visitField(Opcodes.ACC_PRIVATE, "event", "L" + TEST_PKG + "Event;", null, null).visitEnd();
                    defaultConstructor(cw, "java/lang/Object");
                    MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                            "probe", "()I", null, null);
                    mv.visitCode();
                    mv.visitLdcInsn(Type.getObjectType(TEST_PKG + "Event"));
                    mv.visitInsn(Opcodes.POP);
                    mv.visitLdcInsn("example.Event");
                    mv.visitInsn(Opcodes.POP);
                    mv.visitTypeInsn(Opcodes.NEW, TEST_PKG + "Event");
                    mv.visitInsn(Opcodes.DUP);
                    mv.visitMethodInsn(Opcodes.INVOKESPECIAL, TEST_PKG + "Event", "<init>", "()V", false);
                    mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, TEST_PKG + "Event", "helper", "()I", false);
                    mv.visitInsn(Opcodes.IRETURN);
                    mv.visitMaxs(2, 0);
                    mv.visitEnd();
                    MethodVisitor field = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                            "readValue", "()I", null, null);
                    field.visitCode();
                    field.visitTypeInsn(Opcodes.NEW, TEST_PKG + "Event");
                    field.visitInsn(Opcodes.DUP);
                    field.visitMethodInsn(Opcodes.INVOKESPECIAL, TEST_PKG + "Event", "<init>", "()V", false);
                    field.visitFieldInsn(Opcodes.GETFIELD, TEST_PKG + "Event", "value", "I");
                    field.visitInsn(Opcodes.IRETURN);
                    field.visitMaxs(2, 0);
                    field.visitEnd();
                });
    }

    private static byte[] freeClassInOwnPackage(String internalName) {
        return makeClass(internalName,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER, "java/lang/Object", null, cw -> {
                    cw.visitField(Opcodes.ACC_PUBLIC, "f", "I", null, null).visitEnd();
                    defaultConstructor(cw, "java/lang/Object");
                    MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                            "m", "()I", null, null);
                    mv.visitCode();
                    mv.visitInsn(Opcodes.ICONST_1);
                    mv.visitInsn(Opcodes.IRETURN);
                    mv.visitMaxs(1, 0);
                    mv.visitEnd();
                });
    }

    private static byte[] freeClass(String name) {
        return makeClass(TEST_PKG + name,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER, "java/lang/Object", null, cw -> {
                    cw.visitField(Opcodes.ACC_PUBLIC, "f", "I", null, null).visitEnd();
                    defaultConstructor(cw, "java/lang/Object");
                    MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                            "m", "()I", null, null);
                    mv.visitCode();
                    mv.visitInsn(Opcodes.ICONST_1);
                    mv.visitInsn(Opcodes.IRETURN);
                    mv.visitMaxs(1, 0);
                    mv.visitEnd();
                });
    }

    @Test
    void mixinClassReferencingPlainClassFreezesThatClass() {
        byte[] mixin = mixinReferencingEvent();
        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put(TEST_PKG + "Event.class", eventClass());
        classes.put(TEST_PKG + "MixinThing.class", mixin);
        classes.put(TEST_PKG + "Free.class", freeClass("Free"));

        InvisibleNameTransformer.Result result = InvisibleNameTransformer.apply(classes, baseResources(),
                InvisibleNameTransformer.Options.defaults());

        assertSameBytes(mixin, result.classes().get(TEST_PKG + "MixinThing.class"), "Mixin class");
        assertTrue(result.classes().containsKey(TEST_PKG + "Event.class"),
                "class referenced by frozen Mixin bytes keeps its name; keys=" + result.classes().keySet());
        ClassNode event = parse(result.classes().get(TEST_PKG + "Event.class"));
        assertEquals(TEST_PKG + "Event", event.name, "Event class name unchanged");
        assertTrue(event.fields.stream().anyMatch(field -> "value".equals(field.name)), "referenced field kept");
        assertTrue(event.methods.stream().anyMatch(method -> "helper".equals(method.name)),
                "referenced method kept");

        String free = renamedInternal(result.classes(), TEST_PKG + "Free");
        assertTrue(InvisibleNames.containsInvisible(free), "unreferenced class still renamed: " + free);
        ClassNode freeNode = parse(result.classes().get(free + ".class"));
        assertTrue(freeNode.methods.stream().anyMatch(method -> method.name.startsWith("m")
                && InvisibleNames.containsInvisible(method.name)), "unreferenced member still renamed");

        assertTrue(result.protectedClasses() >= 1, "protected class counted");
        assertTrue(result.protectedMembers() >= 2, "referenced members counted: " + result.protectedMembers());
    }

    @Test
    void mixinTargetAndShadowMembersAreFullyProtected() {
        byte[] target = makeClass(TEST_PKG + "Target",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER, "java/lang/Object", null, cw -> {
                    cw.visitField(Opcodes.ACC_PUBLIC, "value", "I", null, null).visitEnd();
                    defaultConstructor(cw, "java/lang/Object");
                    for (String name : new String[]{"compute", "other"}) {
                        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, name, "()I", null, null);
                        mv.visitCode();
                        mv.visitInsn(Opcodes.ICONST_2);
                        mv.visitInsn(Opcodes.IRETURN);
                        mv.visitMaxs(1, 1);
                        mv.visitEnd();
                    }
                });
        byte[] shadowMixin = makeClass(TEST_PKG + "ShadowMixin",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT | Opcodes.ACC_SUPER, "java/lang/Object", null, cw -> {
                    addMixinTargets(cw, "example.Target");
                    FieldVisitor field = cw.visitField(Opcodes.ACC_PRIVATE, "value", "I", null, null);
                    field.visitAnnotation("Lorg/spongepowered/asm/mixin/Shadow;", true).visitEnd();
                    field.visitEnd();
                    MethodVisitor shadow = cw.visitMethod(Opcodes.ACC_PROTECTED | Opcodes.ACC_ABSTRACT,
                            "compute", "()I", null, null);
                    shadow.visitAnnotation("Lorg/spongepowered/asm/mixin/Shadow;", true).visitEnd();
                    shadow.visitEnd();
                    MethodVisitor accessor = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT,
                            "value", "()I", null, null);
                    accessor.visitAnnotation("Lorg/spongepowered/asm/mixin/gen/Accessor;", true).visitEnd();
                    accessor.visitEnd();
                });
        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put(TEST_PKG + "Target.class", target);
        classes.put(TEST_PKG + "ShadowMixin.class", shadowMixin);
        // A class in the same package as a configured Mixin is frozen by the mixin-package rule,
        // so the "free" fixture lives in its own package to stay a rename candidate.
        classes.put("other/Free2.class", freeClassInOwnPackage("other/Free2"));
        Map<String, byte[]> resources = baseResources();
        resources.put("example.mixins.json",
                "{\"package\":\"example.mixin\",\"mixins\":[\"example.ShadowMixin\"]}"
                        .getBytes(StandardCharsets.UTF_8));

        InvisibleNameTransformer.Result result = InvisibleNameTransformer.apply(classes, resources,
                InvisibleNameTransformer.Options.defaults());

        assertSameBytes(shadowMixin, result.classes().get(TEST_PKG + "ShadowMixin.class"), "Mixin class");
        assertTrue(result.classes().containsKey(TEST_PKG + "Target.class"),
                "in-jar Mixin target keeps its name");
        ClassNode targetNode = parse(result.classes().get(TEST_PKG + "Target.class"));
        assertEquals(TEST_PKG + "Target", targetNode.name, "target class name unchanged");
        assertEquals(Set.of("value"), targetNode.fields.stream().map(field -> field.name)
                .collect(java.util.stream.Collectors.toSet()), "target fields unchanged");
        for (MethodNode method : targetNode.methods) {
            if (!"<init>".equals(method.name)) {
                assertFalse(InvisibleNames.containsInvisible(method.name),
                        "@Shadow member must keep its name: " + method.name);
            }
        }
        String free = renamedInternal(result.classes(), "other/Free2");
        assertTrue(InvisibleNames.containsInvisible(free),
                "unrelated class still renamed; keys=" + result.classes().keySet());
        // The mixin-package rule freezes the whole example package (a configured Mixin lives there),
        // so Target's bytes are simply untouched instead of going through the member-protection
        // counters. Free2 lives outside that package and is the only rename candidate.
        assertEquals(0, result.protectedClasses());
        assertEquals(0, result.protectedMembers());
    }

    @Test
    void frozenInterfaceDescriptorKeepsReferencedClass() {
        byte[] listener = makeClass(TEST_PKG + "Listener",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT,
                "java/lang/Object", null, cw -> cw.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT, "on", "(L" + TEST_PKG + "Payload;)V",
                null, null).visitEnd());
        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put(TEST_PKG + "Listener.class", listener);
        classes.put(TEST_PKG + "Payload.class", freeClass("Payload"));
        classes.put(TEST_PKG + "Free3.class", freeClass("Free3"));

        InvisibleNameTransformer.Result result = InvisibleNameTransformer.apply(classes, Map.of(),
                InvisibleNameTransformer.Options.defaults());

        assertSameBytes(listener, result.classes().get(TEST_PKG + "Listener.class"),
                "interface (frozen) unchanged");
        assertTrue(result.classes().containsKey(TEST_PKG + "Payload.class"),
                "class referenced from frozen interface descriptor keeps its name");
        String freeName = renamedInternal(result.classes(), TEST_PKG + "Free3");
        assertTrue(InvisibleNames.containsInvisible(freeName), "unreferenced class still renamed");
    }

    @Test
    void scalesToHundredsOfClassesWithoutLosingNames() {
        Map<String, byte[]> classes = new LinkedHashMap<>();
        for (int c = 0; c < 120; c++) {
            int index = c;
            String name = TEST_PKG + "scale/C" + c;
            classes.put(name + ".class", makeClass(name,
                    Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER, "java/lang/Object", null, cw -> {
                        defaultConstructor(cw, "java/lang/Object");
                        for (int m = 0; m < 5; m++) {
                            MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                                    "m" + m, "()I", null, null);
                            mv.visitCode();
                            mv.visitIntInsn(Opcodes.BIPUSH, index + m);
                            mv.visitInsn(Opcodes.IRETURN);
                            mv.visitMaxs(1, 0);
                            mv.visitEnd();
                        }
                    }));
        }
        InvisibleNameTransformer.Result result = InvisibleNameTransformer.apply(classes, Map.of(),
                InvisibleNameTransformer.Options.defaults());
        assertEquals(120, result.classesRenamed());
        assertEquals(600, result.methodsRenamed());
        assertEquals(120, result.classes().size());
        for (Map.Entry<String, byte[]> entry : new TreeMap<>(result.classes()).entrySet()) {
            ClassNode node = parse(entry.getValue());
            assertEquals(entry.getKey().substring(0, entry.getKey().length() - ".class".length()), node.name);
        }
    }
}
