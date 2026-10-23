package dev.chimera.transform.init;

import dev.chimera.core.ChimeraClassWriter;
import dev.chimera.core.ClassPool;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.util.CheckClassAdapter;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static dev.chimera.transform.init.InitFixtures.BRANCH_CTOR;
import static dev.chimera.transform.init.InitFixtures.ENUM;
import static dev.chimera.transform.init.InitFixtures.FINAL;
import static dev.chimera.transform.init.InitFixtures.INTERFACE;
import static dev.chimera.transform.init.InitFixtures.MIXIN;
import static dev.chimera.transform.init.InitFixtures.ORDER;
import static dev.chimera.transform.init.InitFixtures.RECORD;
import static dev.chimera.transform.init.InitFixtures.STATIC_BRANCH;
import static dev.chimera.transform.init.InitFixtures.SUBJECT;
import static dev.chimera.transform.init.InitFixtures.TRY_CATCH;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** G4 acceptance: field-init sinking keeps per-method behaviour, stats and verification green. */
class FieldInitSinkTest {

    @Test
    void sinksInstanceAndStaticConstantsAndKeepsBehaviour() throws Exception {
        byte[] original = InitFixtures.subject();
        FieldInitSink.TransformResult result = FieldInitSink.transformClass(original);
        FieldInitSink.Stats stats = result.stats();

        assertEquals(1, stats.classesVisited());
        assertEquals(0, stats.classesSkipped());
        assertEquals(7, stats.sunkFields(), "5 instance + 2 static constant assignments");
        assertEquals(4, stats.skipped());
        assertEquals(2, stats.sinkMethods());
        assertEquals(2, stats.skipCount(FieldInitSink.SkipReason.FINAL_FIELD));
        assertEquals(2, stats.skipCount(FieldInitSink.SkipReason.NON_CONSTANT));
        assertEquals("non_constant", FieldInitSink.SkipReason.NON_CONSTANT.label());

        assertTrue(instructionCount(result.bytes(), "<init>")
                        < instructionCount(original, "<init>"), "constructor must shrink");
        assertTrue(instructionCount(result.bytes(), "<clinit>")
                        < instructionCount(original, "<clinit>"), "class initializer must shrink");

        List<MethodNode> helpers = helperMethods(result.bytes());
        assertEquals(2, helpers.size());
        for (MethodNode helper : helpers) {
            assertEquals(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                    helper.access & (Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC));
            assertEquals(Type.VOID_TYPE, Type.getReturnType(helper.desc));
        }
        assertFalse(hasHelperCallIn(original, "<init>"), "original constructor has no helper call");
        assertTrue(hasHelperCallIn(result.bytes(), "<init>"));
        assertTrue(hasHelperCallIn(result.bytes(), "<clinit>"));

        structuralCheck(original);
        structuralCheck(result.bytes());
        TestLoader originalLoader = new TestLoader(Map.of(SUBJECT, original));
        TestLoader transformedLoader = new TestLoader(Map.of(SUBJECT, result.bytes()));
        dataflowCheck(result.bytes(), transformedLoader);

        Class<?> originalType = Class.forName(SUBJECT.replace('/', '.'), true, originalLoader);
        Class<?> transformedType = Class.forName(SUBJECT.replace('/', '.'), true, transformedLoader);
        Object before = originalType.getDeclaredConstructor(int.class).newInstance(5);
        Object after = transformedType.getDeclaredConstructor(int.class).newInstance(5);

        assertEquals(1, callInt(before, "getA"));
        assertEquals(42, callInt(before, "getB"));
        assertEquals("hello", call(before, "text"));
        assertEquals(5, callInt(before, "getArgument"));
        assertEquals(7, callInt(before, "getFixed"));
        assertEquals(5, callStaticInt(originalType, "getSa"));
        assertEquals("static", callStatic(originalType, "getSs"));
        assertEquals(3, callStaticInt(originalType, "getSf"));
        assertEquals(8, callStaticInt(originalType, "getSnapshot"));
        assertEquals(1234567890124L, ((Number) call(before, "longValue")).longValue());
        assertEquals(2.5d, ((Number) call(before, "doubleValue")).doubleValue(), 0.0d);

        assertEquals(1, callInt(after, "getA"));
        assertEquals(42, callInt(after, "getB"));
        assertEquals("hello", call(after, "text"));
        assertEquals(5, callInt(after, "getArgument"));
        assertEquals(7, callInt(after, "getFixed"));
        assertEquals(5, callStaticInt(transformedType, "getSa"));
        assertEquals("static", callStatic(transformedType, "getSs"));
        assertEquals(3, callStaticInt(transformedType, "getSf"));
        assertEquals(8, callStaticInt(transformedType, "getSnapshot"));
        assertEquals(1234567890124L, ((Number) call(after, "longValue")).longValue());
        assertEquals(2.5d, ((Number) call(after, "doubleValue")).doubleValue(), 0.0d);

        Random random = new Random(0x5EEDL);
        for (int i = 0; i < 400; i++) {
            int n = random.nextInt(48);
            int x = random.nextInt();
            assertEquals(callInt(before, "sum", new Class<?>[]{int.class}, n),
                    callInt(after, "sum", new Class<?>[]{int.class}, n),
                    "sum(" + n + ")");
            assertEquals(callInt(before, "branch", new Class<?>[]{int.class}, x),
                    callInt(after, "branch", new Class<?>[]{int.class}, x),
                    "branch(" + x + ")");
            assertEquals(callInt(before, "throwing", new Class<?>[]{int.class}, Math.abs(x)),
                    callInt(after, "throwing", new Class<?>[]{int.class}, Math.abs(x)));
        }

        Throwable originalError = causeOf(() ->
                call(before, "throwing", new Class<?>[]{int.class}, -1));
        Throwable transformedError = causeOf(() ->
                call(after, "throwing", new Class<?>[]{int.class}, -1));
        assertEquals(originalError.getClass(), transformedError.getClass());
        assertEquals(originalError.getMessage(), transformedError.getMessage());
    }

    @Test
    void preservesInitializationOrderAcrossSideEffects() throws Exception {
        byte[] original = InitFixtures.orderSubject();
        FieldInitSink.TransformResult result = FieldInitSink.transformClass(original);
        FieldInitSink.Stats stats = result.stats();

        assertEquals(3, stats.sunkFields());
        assertEquals(2, stats.sinkMethods());
        assertEquals(3, stats.skipCount(FieldInitSink.SkipReason.STATIC_FIELD_IN_INIT));

        TestLoader loader = new TestLoader(Map.of(ORDER, result.bytes()));
        Class<?> type = Class.forName(ORDER.replace('/', '.'), true, loader);
        Object instance = type.getDeclaredConstructor().newInstance();
        assertEquals(1, callInt(instance, "getA"));
        assertEquals(2, callInt(instance, "getB"));
        assertEquals(9, callInt(instance, "getC"));
        assertEquals(1, callStaticInt(type, "getObservedA"));
        assertEquals(2, callStaticInt(type, "getObservedB"));
        assertEquals(9, callStaticInt(type, "getObservedC"));
        structuralCheck(result.bytes());
        dataflowCheck(result.bytes(), loader);
    }

    @Test
    void leavesFinalFieldsInPlaceAndKeepsFinalSemantics() throws Exception {
        byte[] original = InitFixtures.finalSubject();
        FieldInitSink.TransformResult result = FieldInitSink.transformClass(original);
        FieldInitSink.Stats stats = result.stats();

        assertEquals(0, stats.sunkFields());
        assertEquals(3, stats.skipped());
        assertEquals(2, stats.skipCount(FieldInitSink.SkipReason.FINAL_FIELD));
        assertEquals(1, stats.skipCount(FieldInitSink.SkipReason.VOLATILE_FIELD));
        assertEquals(0, stats.sinkMethods());
        assertTrue(helperMethods(result.bytes()).isEmpty());

        ClassNode node = read(result.bytes());
        assertTrue(isFinalField(node, "v"));
        assertTrue(isFinalField(node, "K"));

        TestLoader loader = new TestLoader(Map.of(FINAL, result.bytes()));
        Class<?> type = Class.forName(FINAL.replace('/', '.'), true, loader);
        Object instance = type.getDeclaredConstructor().newInstance();
        assertEquals(5, callInt(instance, "getV"));
        assertEquals(11, callInt(instance, "getVv"));
        assertEquals(7, callStaticInt(type, "getK"));
        assertTrue(Modifier.isFinal(type.getDeclaredField("v").getModifiers()));
        assertTrue(Modifier.isFinal(type.getDeclaredField("K").getModifiers()));
        structuralCheck(result.bytes());
        dataflowCheck(result.bytes(), loader);
    }

    @Test
    void skipsTryCatchConstructorsAndParameterDependentValues() throws Exception {
        byte[] original = InitFixtures.tryCatchSubject();
        FieldInitSink.TransformResult result = FieldInitSink.transformClass(original);
        FieldInitSink.Stats stats = result.stats();

        assertEquals(0, stats.sunkFields());
        assertEquals(3, stats.skipped());
        assertEquals(3, stats.skipCount(FieldInitSink.SkipReason.TRY_CATCH));
        assertEquals(0, stats.sinkMethods());
        assertTrue(helperMethods(result.bytes()).isEmpty());

        TestLoader loader = new TestLoader(Map.of(TRY_CATCH, result.bytes()));
        Class<?> type = Class.forName(TRY_CATCH.replace('/', '.'), true, loader);
        Object instance = type.getDeclaredConstructor().newInstance();
        assertEquals(1, callInt(instance, "getA"));
        assertEquals(2, callInt(instance, "getB"));
        structuralCheck(result.bytes());
        dataflowCheck(result.bytes(), loader);
    }

    @Test
    void sinksAssignmentsInConstructorBranchesWithoutCrossingMergePoints() throws Exception {
        byte[] original = InitFixtures.branchCtorSubject();
        FieldInitSink.TransformResult result = FieldInitSink.transformClass(original);
        FieldInitSink.Stats stats = result.stats();

        assertEquals(3, stats.sunkFields());
        assertEquals(3, stats.sinkMethods(), "one helper per branch/merge-separated run");
        assertEquals(0, stats.skipped());

        TestLoader loader = new TestLoader(Map.of(BRANCH_CTOR, result.bytes()));
        Class<?> type = Class.forName(BRANCH_CTOR.replace('/', '.'), true, loader);
        Object positive = type.getDeclaredConstructor(int.class).newInstance(1);
        Object negative = type.getDeclaredConstructor(int.class).newInstance(-1);
        assertEquals(1, callInt(positive, "getA"));
        assertEquals(3, callInt(positive, "getB"));
        assertEquals(2, callInt(negative, "getA"));
        assertEquals(3, callInt(negative, "getB"));
        structuralCheck(result.bytes());
        dataflowCheck(result.bytes(), loader);
    }

    @Test
    void sinksStaticAssignmentsAtBranchMergePoints() throws Exception {
        for (int flag : new int[]{0, 1}) {
            byte[] original = InitFixtures.staticBranchSubject(flag);
            FieldInitSink.TransformResult result = FieldInitSink.transformClass(original);
            FieldInitSink.Stats stats = result.stats();
            assertEquals(2, stats.sunkFields(), "flag=" + flag);
            assertEquals(2, stats.sinkMethods(), "flag=" + flag);
            assertEquals(0, stats.skipped(), "flag=" + flag);

            TestLoader loader = new TestLoader(Map.of(STATIC_BRANCH, result.bytes()));
            Class<?> type = Class.forName(STATIC_BRANCH.replace('/', '.'), true, loader);
            assertEquals(flag, callStaticInt(type, "getFlag"));
            assertEquals(flag, callStaticInt(type, "getA"), "branch skipping the first pair");
            assertEquals("x", callStatic(type, "getB"));
            structuralCheck(result.bytes());
            dataflowCheck(result.bytes(), loader);
        }
    }

    @Test
    void skipsMixinRecordEnumAndInterfaceClasses() {
        byte[] mixin = InitFixtures.mixinSubject();
        FieldInitSink.TransformResult mixinResult = FieldInitSink.transformClass(mixin);
        assertArrayEquals(mixin, mixinResult.bytes(), "Mixin bytes must be preserved verbatim");
        assertEquals(1, mixinResult.stats().classesSkipped());
        assertEquals(0, mixinResult.stats().sunkFields());

        Map<String, byte[]> others = new java.util.LinkedHashMap<>();
        others.put(RECORD, InitFixtures.recordSubject());
        others.put(ENUM, InitFixtures.enumSubject());
        others.put(INTERFACE, InitFixtures.interfaceSubject());
        for (Map.Entry<String, byte[]> entry : others.entrySet()) {
            FieldInitSink.TransformResult result = FieldInitSink.transformClass(entry.getValue());
            assertEquals(1, result.stats().classesSkipped(), entry.getKey());
            assertEquals(0, result.stats().sunkFields(), entry.getKey());
            assertEquals(0, result.stats().sinkMethods(), entry.getKey());
            assertTrue(helperMethods(result.bytes()).isEmpty(), entry.getKey());
            structuralCheck(entry.getValue());
        }
    }

    @Test
    void isIdempotent() throws Exception {
        byte[] original = InitFixtures.subject();
        FieldInitSink.TransformResult first = FieldInitSink.transformClass(original);
        FieldInitSink.TransformResult second = FieldInitSink.transformClass(first.bytes());

        assertEquals(0, second.stats().sunkFields(), "a second pass must not sink anything new");
        assertEquals(0, second.stats().sinkMethods());
        assertArrayEquals(first.bytes(), second.bytes(), "second pass must be byte-identical");

        TestLoader loader = new TestLoader(Map.of(SUBJECT, second.bytes()));
        Class<?> type = Class.forName(SUBJECT.replace('/', '.'), true, loader);
        Object instance = type.getDeclaredConstructor(int.class).newInstance(3);
        assertEquals(42, callInt(instance, "getB"));
        assertEquals(5, callStaticInt(type, "getSa"));
        structuralCheck(second.bytes());
        dataflowCheck(second.bytes(), loader);
    }

    @Test
    void survivesEngineFrameRecomputation() throws Exception {
        byte[] transformed = FieldInitSink.transformClass(InitFixtures.subject()).bytes();
        Map<String, byte[]> classes = Map.of(SUBJECT, transformed);
        byte[] rewritten = engineWrite(transformed, classes);

        TestLoader loader = new TestLoader(Map.of(SUBJECT, rewritten));
        Class<?> type = Class.forName(SUBJECT.replace('/', '.'), true, loader);
        Object instance = type.getDeclaredConstructor(int.class).newInstance(9);
        assertEquals(42, callInt(instance, "getB"));
        assertEquals(9, callInt(instance, "getArgument"));
        assertEquals(5, callStaticInt(type, "getSa"));
        assertEquals(8, callStaticInt(type, "getSnapshot"));
        assertEquals(156, callInt(instance, "sum", new Class<?>[]{int.class}, 3));
        structuralCheck(rewritten);
        dataflowCheck(rewritten, loader);
    }

    // ------------------------------------------------------------------ helpers

    private static byte[] engineWrite(byte[] bytes, Map<String, byte[]> classes) {
        ClassReader reader = new ClassReader(bytes);
        ClassNode node = new ClassNode();
        reader.accept(node, ClassReader.EXPAND_FRAMES);
        ClassWriter writer = new ChimeraClassWriter(
                ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS, new ClassPool(classes));
        node.accept(writer);
        return writer.toByteArray();
    }

    private static int instructionCount(byte[] bytes, String methodName) {
        ClassNode node = read(bytes);
        for (MethodNode method : node.methods) {
            if (methodName.equals(method.name)) {
                int count = 0;
                for (var insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (insn.getOpcode() >= 0) {
                        count++;
                    }
                }
                return count;
            }
        }
        throw new AssertionError("method not found: " + methodName);
    }

    private static boolean hasHelperCallIn(byte[] bytes, String methodName) {
        ClassNode node = read(bytes);
        for (MethodNode method : node.methods) {
            if (!methodName.equals(method.name)) {
                continue;
            }
            for (var insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof org.objectweb.asm.tree.MethodInsnNode call
                        && call.name.startsWith("chimera$init$")) {
                    return true;
                }
            }
        }
        return false;
    }

    private static List<MethodNode> helperMethods(byte[] bytes) {
        List<MethodNode> helpers = new ArrayList<>();
        for (MethodNode method : read(bytes).methods) {
            if (method.name.startsWith("chimera$init$")) {
                helpers.add(method);
            }
        }
        return helpers;
    }

    private static boolean isFinalField(ClassNode node, String name) {
        for (var field : node.fields) {
            if (name.equals(field.name)) {
                return (field.access & Opcodes.ACC_FINAL) != 0;
            }
        }
        return false;
    }

    private static ClassNode read(byte[] bytes) {
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return node;
    }

    private static void structuralCheck(byte[] bytes) {
        new ClassReader(bytes).accept(new CheckClassAdapter(new ClassWriter(0), false), 0);
    }

    private static void dataflowCheck(byte[] bytes, ClassLoader loader) {
        StringWriter diagnostics = new StringWriter();
        CheckClassAdapter.verify(new ClassReader(bytes), loader, false, new PrintWriter(diagnostics));
        assertEquals("", diagnostics.toString().trim(), diagnostics.toString());
    }

    private static Object call(Object target, String name, Class<?>[] types, Object... args)
            throws Exception {
        Method method = target.getClass().getMethod(name, types);
        return method.invoke(target, args);
    }

    private static Object call(Object target, String name) throws Exception {
        return call(target, name, new Class<?>[0]);
    }

    private static int callInt(Object target, String name) throws Exception {
        return ((Number) call(target, name)).intValue();
    }

    private static int callInt(Object target, String name, Class<?>[] types, Object... args)
            throws Exception {
        return ((Number) call(target, name, types, args)).intValue();
    }

    private static Object callStatic(Class<?> type, String name) throws Exception {
        return callStatic(type, name, new Class<?>[0]);
    }

    private static Object callStatic(Class<?> type, String name, Class<?>[] types, Object... args)
            throws Exception {
        return type.getMethod(name, types).invoke(null, args);
    }

    private static int callStaticInt(Class<?> type, String name) throws Exception {
        return ((Number) callStatic(type, name)).intValue();
    }

    private static Throwable causeOf(ThrowingRunnable runnable) {
        InvocationTargetException thrown = assertThrows(InvocationTargetException.class, runnable::run);
        assertNotNull(thrown.getCause());
        return thrown.getCause();
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    private static final class TestLoader extends ClassLoader {
        private final Map<String, byte[]> classes;

        private TestLoader(Map<String, byte[]> classes) {
            super(FieldInitSinkTest.class.getClassLoader());
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
}
