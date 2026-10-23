package dev.chimera.transform.wrap;

import dev.chimera.core.ChimeraClassWriter;
import dev.chimera.core.ClassPool;
import dev.chimera.transform.indy.MemberIdRegistry;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.util.CheckClassAdapter;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import static dev.chimera.transform.wrap.WrapFixtures.CALC;
import static dev.chimera.transform.wrap.WrapFixtures.INTERFACE;
import static dev.chimera.transform.wrap.WrapFixtures.MATH;
import static dev.chimera.transform.wrap.WrapFixtures.MIXIN;
import static dev.chimera.transform.wrap.WrapFixtures.SUBJECT;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** B6 acceptance: wrapper calls keep per-method behaviour, stats, verification and idempotency. */
class InvokeWrapperTest {

    @Test
    void directModeRewritesExternalCallsAndPreservesBehaviour() throws Exception {
        byte[] original = WrapFixtures.subject();
        InvokeWrapper.TransformResult result = InvokeWrapper.transformClass(original);
        InvokeWrapper.Stats stats = result.stats();

        assertEquals(16, stats.invokeSites());
        assertEquals(10, stats.rewritten());
        assertEquals(6, stats.skipped());
        assertEquals(7, stats.rewrittenStatic());
        assertEquals(3, stats.rewrittenVirtual());
        assertEquals(8, stats.wrappersGenerated());
        assertEquals(8, stats.targets().size());
        assertEquals(1, stats.skipCount(InvokeWrapper.SkipReason.METHOD_INIT));
        assertEquals(1, stats.skipCount(InvokeWrapper.SkipReason.METHOD_CLINIT));
        assertEquals(2, stats.skipCount(InvokeWrapper.SkipReason.WHITELIST));
        assertEquals(1, stats.skipCount(InvokeWrapper.SkipReason.SELF_CLASS));
        assertEquals(1, stats.skipCount(InvokeWrapper.SkipReason.REFLECTION_SENSITIVE));

        List<MethodNode> wrappers = wrapperMethods(result.bytes());
        assertEquals(8, wrappers.size());
        for (MethodNode wrapper : wrappers) {
            assertEquals(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                    wrapper.access & (Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC));
        }

        ClassNode transformed = read(result.bytes());
        MethodNode staticPath = find(transformed, "staticPath");
        assertTrue(callsWrapper(staticPath), "staticPath must call its generated wrapper");
        assertFalse(callsOwner(staticPath, MATH), "staticPath must not name MathApi directly");
        MethodNode constructor = find(transformed, "<init>");
        assertTrue(callsOwner(constructor, MATH), "constructors are skipped and keep direct calls");
        assertFalse(callsWrapper(constructor), "constructors are never rewritten");

        structuralCheck(original);
        structuralCheck(result.bytes());
        Map<String, byte[]> originalClasses = classes(original);
        Map<String, byte[]> rewrittenClasses = classes(result.bytes());
        TestLoader originalLoader = new TestLoader(originalClasses);
        TestLoader rewrittenLoader = new TestLoader(rewrittenClasses);
        dataflowCheck(result.bytes(), rewrittenLoader);

        Class<?> originalType = Class.forName(SUBJECT.replace('/', '.'), true, originalLoader);
        Class<?> transformedType = Class.forName(SUBJECT.replace('/', '.'), true, rewrittenLoader);
        Class<?> originalCalc = Class.forName(CALC.replace('/', '.'), true, originalLoader);
        Class<?> transformedCalc = Class.forName(CALC.replace('/', '.'), true, rewrittenLoader);
        Class<?> originalMath = Class.forName(MATH.replace('/', '.'), true, originalLoader);
        Class<?> transformedMath = Class.forName(MATH.replace('/', '.'), true, rewrittenLoader);
        Object before = originalCalc.getDeclaredConstructor().newInstance();
        Object after = transformedCalc.getDeclaredConstructor().newInstance();

        Random random = new Random(0xB6B6L);
        for (int i = 0; i < 400; i++) {
            int a = random.nextInt();
            int b = random.nextInt();
            int n = random.nextInt(40);
            assertEquals(
                    callStaticInt(originalType, "staticPath", new Class<?>[]{int.class, int.class}, a, b),
                    callStaticInt(transformedType, "staticPath", new Class<?>[]{int.class, int.class}, a, b));
            assertEquals(
                    callStaticInt(originalType, "virtualPath",
                            new Class<?>[]{originalCalc, int.class}, before, a),
                    callStaticInt(transformedType, "virtualPath",
                            new Class<?>[]{transformedCalc, int.class}, after, a));
            assertEquals(
                    callStaticInt(originalType, "branchy", new Class<?>[]{int.class}, a),
                    callStaticInt(transformedType, "branchy", new Class<?>[]{int.class}, a));
            assertEquals(
                    callStaticInt(originalType, "loopy", new Class<?>[]{int.class}, n),
                    callStaticInt(transformedType, "loopy", new Class<?>[]{int.class}, n));
            assertEquals(
                    callStaticLong(originalType, "longPath", new Class<?>[]{long.class, long.class}, a, b),
                    callStaticLong(transformedType, "longPath", new Class<?>[]{long.class, long.class}, a, b));
            assertEquals(
                    callStaticDouble(originalType, "doublePath",
                            new Class<?>[]{double.class, double.class}, a / 3.0d, b / 7.0d),
                    callStaticDouble(transformedType, "doublePath",
                            new Class<?>[]{double.class, double.class}, a / 3.0d, b / 7.0d),
                    0.0d);
        }

        assertEquals("6", callStatic(originalType, "exceptionPath",
                new Class<?>[]{originalCalc, int.class}, before, 2));
        assertEquals("6", callStatic(transformedType, "exceptionPath",
                new Class<?>[]{transformedCalc, int.class}, after, 2));
        Throwable originalError = causeOf(() -> callStatic(originalType, "exceptionPath",
                new Class<?>[]{originalCalc, int.class}, before, -3));
        Throwable transformedError = causeOf(() -> callStatic(transformedType, "exceptionPath",
                new Class<?>[]{transformedCalc, int.class}, after, -3));
        assertEquals(originalError.getClass(), transformedError.getClass());
        assertEquals(originalError.getMessage(), transformedError.getMessage());

        assertEquals(7, callStaticInt(originalType, "selfPath", new Class<?>[]{int.class}, 1));
        assertEquals(7, callStaticInt(transformedType, "selfPath", new Class<?>[]{int.class}, 1));
        assertEquals(0, callStaticInt(originalType, "reflectionPath",
                new Class<?>[]{String.class}, "ignored"));
        assertEquals(0, callStaticInt(transformedType, "reflectionPath",
                new Class<?>[]{String.class}, "ignored"));

        int originalCounter = callStaticInt(originalMath, "counter");
        int transformedCounter = callStaticInt(transformedMath, "counter");
        callStatic(originalType, "voidPath");
        callStatic(transformedType, "voidPath");
        assertEquals(originalCounter + 1, callStaticInt(originalMath, "counter"));
        assertEquals(transformedCounter + 1, callStaticInt(transformedMath, "counter"));

        // Constructors still execute their deliberately skipped direct call.
        originalType.getDeclaredConstructor().newInstance();
        transformedType.getDeclaredConstructor().newInstance();
    }

    @Test
    void memberIdModeUsesRegistryCacheAndPreservesBehaviour() throws Exception {
        byte[] original = WrapFixtures.subject();
        InvokeWrapper.TransformResult result =
                InvokeWrapper.transformClass(original, InvokeWrapper.Options.memberId());
        InvokeWrapper.Stats stats = result.stats();
        assertEquals(16, stats.invokeSites());
        assertEquals(10, stats.rewritten());
        assertEquals(8, stats.wrappersGenerated());

        ClassNode transformed = read(result.bytes());
        MethodNode staticPath = find(transformed, "staticPath");
        assertTrue(callsOwner(wrapperMethods(result.bytes()).get(0),
                "dev/chimera/transform/wrap/WrapperSupport"),
                "MEMBER_ID wrappers must resolve through WrapperSupport");
        assertFalse(callsOwner(staticPath, MATH));
        structuralCheck(result.bytes());

        Map<String, byte[]> rewrittenClasses = classes(result.bytes());
        TestLoader loader = new TestLoader(rewrittenClasses);
        dataflowCheck(result.bytes(), loader);

        MemberIdRegistry.clearForTests();
        WrapperSupport.clearForTests();
        Class<?> type = Class.forName(SUBJECT.replace('/', '.'), true, loader);
        Class<?> calc = Class.forName(CALC.replace('/', '.'), true, loader);
        MemberIdRegistry.loadMemberTable(InvokeWrapper.encodeTargetTable(stats), loader);

        Object calcInstance = calc.getDeclaredConstructor().newInstance();
        assertEquals(10, callStaticInt(type, "staticPath", new Class<?>[]{int.class, int.class}, 5, 2));
        assertEquals(16, callStaticInt(type, "virtualPath", new Class<?>[]{calc, int.class}, calcInstance, 4));
        assertEquals(14, callStaticInt(type, "branchy", new Class<?>[]{int.class}, 7));
        assertEquals(0, callStaticInt(type, "loopy", new Class<?>[]{int.class}, 0));
        assertEquals("9", callStatic(type, "exceptionPath", new Class<?>[]{calc, int.class}, calcInstance, 3));
        assertEquals(3L, ((Number) callStatic(type, "longPath",
                new Class<?>[]{long.class, long.class}, 1L, 2L)).longValue());
        assertEquals(4.0d, ((Number) callStatic(type, "doublePath",
                new Class<?>[]{double.class, double.class}, 1.5d, 2.5d)).doubleValue(), 0.0d);
        callStatic(type, "voidPath");

        assertEquals(8, WrapperSupport.resolutions(), "each distinct wrapper target resolves once");
        assertEquals(0, MemberIdRegistry.misses());

        // Repeat calls must hit the cache, not the registry.
        callStaticInt(type, "staticPath", new Class<?>[]{int.class, int.class}, 1, 1);
        callStaticInt(type, "virtualPath", new Class<?>[]{calc, int.class}, calcInstance, 2);
        callStatic(type, "voidPath");
        assertEquals(8, WrapperSupport.resolutions());

        Throwable error = causeOf(() -> callStatic(type, "exceptionPath",
                new Class<?>[]{calc, int.class}, calcInstance, -4));
        assertEquals(IllegalStateException.class, error.getClass());
        assertEquals("calc-negative", error.getMessage());

        InvokeWrapper.TransformResult again =
                InvokeWrapper.transformClass(result.bytes(), InvokeWrapper.Options.memberId());
        assertEquals(0, again.stats().rewritten());
        assertArrayEquals(result.bytes(), again.bytes());
    }

    @Test
    void memberIdModeBoxesPrimitiveArgumentsAndUnboxesReturns() throws Exception {
        byte[] original = WrapFixtures.primitiveSubject();
        InvokeWrapper.TransformResult result =
                InvokeWrapper.transformClass(original, InvokeWrapper.Options.memberId());
        assertEquals(5, result.stats().invokeSites());
        assertEquals(5, result.stats().rewritten());
        assertEquals(5, result.stats().wrappersGenerated());

        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put(WrapFixtures.PRIMITIVE_API, WrapFixtures.primitiveApi());
        classes.put(WrapFixtures.PRIMITIVE_SUBJECT, result.bytes());
        TestLoader loader = new TestLoader(classes);
        dataflowCheck(result.bytes(), loader);

        MemberIdRegistry.clearForTests();
        WrapperSupport.clearForTests();
        Class<?> type = Class.forName(WrapFixtures.PRIMITIVE_SUBJECT.replace('/', '.'), true, loader);
        MemberIdRegistry.loadMemberTable(InvokeWrapper.encodeTargetTable(result.stats()), loader);

        assertEquals(Boolean.TRUE, callStatic(type, "flagPath", new Class<?>[]{int.class}, 5));
        assertEquals(Boolean.FALSE, callStatic(type, "flagPath", new Class<?>[]{int.class}, -1));
        assertEquals(Boolean.FALSE, callStatic(type, "notPath", new Class<?>[]{boolean.class}, true));
        assertEquals(Boolean.TRUE, callStatic(type, "notPath", new Class<?>[]{boolean.class}, false));
        assertEquals(Byte.valueOf((byte) -7),
                callStatic(type, "bytePath", new Class<?>[]{byte.class}, (byte) -7));
        assertEquals(Character.valueOf('A'),
                callStatic(type, "charPath", new Class<?>[]{char.class}, 'A'));
        assertEquals(Short.valueOf((short) 1234),
                callStatic(type, "shortPath", new Class<?>[]{short.class}, (short) 1234));
        assertEquals(5, WrapperSupport.resolutions());
        structuralCheck(result.bytes());
    }

    @Test
    void mixinClassesArePreservedVerbatim() {
        byte[] mixin = WrapFixtures.mixinSubject();
        assertTrue(InvokeWrapper.isMixinClass(read(mixin)));
        InvokeWrapper.TransformResult result = InvokeWrapper.transformClass(mixin);
        assertArrayEquals(mixin, result.bytes(), "Mixin bytes must be preserved verbatim");
        assertEquals(2, result.stats().invokeSites());
        assertEquals(0, result.stats().rewritten());
        assertEquals(2, result.stats().skipCount(InvokeWrapper.SkipReason.MIXIN_CLASS));
        assertEquals(1, result.stats().preservedMixinClasses());
        structuralCheck(mixin);
    }

    @Test
    void honoursWhitelistAndReportsSkipReasons() {
        byte[] original = WrapFixtures.subject();
        Set<String> whitelist = new java.util.LinkedHashSet<>(InvokeWrapper.Options.DEFAULT_WHITELIST);
        whitelist.add("fixtures/");
        InvokeWrapper.TransformResult result = InvokeWrapper.transformClass(original,
                InvokeWrapper.Options.direct(whitelist));
        InvokeWrapper.Stats stats = result.stats();

        assertEquals(16, stats.invokeSites());
        assertEquals(0, stats.rewritten());
        assertEquals(0, stats.wrappersGenerated());
        assertEquals(12, stats.skipCount(InvokeWrapper.SkipReason.WHITELIST));
        assertEquals(1, stats.skipCount(InvokeWrapper.SkipReason.METHOD_INIT));
        assertEquals(1, stats.skipCount(InvokeWrapper.SkipReason.METHOD_CLINIT));
        assertEquals(1, stats.skipCount(InvokeWrapper.SkipReason.SELF_CLASS));
        assertEquals(1, stats.skipCount(InvokeWrapper.SkipReason.REFLECTION_SENSITIVE));
        assertTrue(wrapperMethods(result.bytes()).isEmpty());
        structuralCheck(result.bytes());
    }

    @Test
    void isIdempotent() throws Exception {
        byte[] original = WrapFixtures.subject();
        InvokeWrapper.TransformResult first = InvokeWrapper.transformClass(original);
        InvokeWrapper.TransformResult second = InvokeWrapper.transformClass(first.bytes());

        assertEquals(0, second.stats().rewritten(), "second pass must not rewrite again");
        assertEquals(0, second.stats().wrappersGenerated());
        assertArrayEquals(first.bytes(), second.bytes(), "second pass must be byte-identical");

        TestLoader loader = new TestLoader(classes(second.bytes()));
        Class<?> type = Class.forName(SUBJECT.replace('/', '.'), true, loader);
        assertEquals(10, callStaticInt(type, "staticPath", new Class<?>[]{int.class, int.class}, 5, 2));
        structuralCheck(second.bytes());
        dataflowCheck(second.bytes(), loader);
    }

    @Test
    void wrapsInterfaceStaticCallsWithInterfaceOwnerFlag() throws Exception {
        byte[] original = WrapFixtures.wrapInterface();
        InvokeWrapper.TransformResult result = InvokeWrapper.transformClass(original);
        InvokeWrapper.Stats stats = result.stats();
        assertEquals(1, stats.invokeSites());
        assertEquals(1, stats.rewritten());
        assertEquals(1, stats.wrappersGenerated());

        ClassNode node = read(result.bytes());
        MethodNode viaStatic = find(node, "viaStatic");
        boolean wrapperCallWithInterfaceFlag = false;
        for (AbstractInsnNode insn = viaStatic.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof MethodInsnNode call && call.name.startsWith("chimera$invoke$")) {
                wrapperCallWithInterfaceFlag = call.itf;
            }
        }
        assertTrue(wrapperCallWithInterfaceFlag, "interface call sites must use InterfaceMethodref");

        Map<String, byte[]> map = new LinkedHashMap<>();
        map.put(INTERFACE, result.bytes());
        map.put(MATH, WrapFixtures.mathApi());
        TestLoader loader = new TestLoader(map);
        Class<?> type = Class.forName(INTERFACE.replace('/', '.'), true, loader);
        assertEquals(8, callStaticInt(type, "viaStatic", new Class<?>[]{int.class}, 4));
        structuralCheck(result.bytes());
        dataflowCheck(result.bytes(), loader);

        Map<String, byte[]> engineClasses = new LinkedHashMap<>(map);
        byte[] engineBytes = engineWrite(result.bytes(), engineClasses);
        engineClasses.put(INTERFACE, engineBytes);
        TestLoader engineLoader = new TestLoader(engineClasses);
        Class<?> engineType = Class.forName(INTERFACE.replace('/', '.'), true, engineLoader);
        assertEquals(8, callStaticInt(engineType, "viaStatic", new Class<?>[]{int.class}, 4));
        dataflowCheck(engineBytes, engineLoader);
    }

    @Test
    void survivesEngineFrameRecomputation() throws Exception {
        byte[] transformed = InvokeWrapper.transformClass(WrapFixtures.subject()).bytes();
        Map<String, byte[]> classes = classes(transformed);
        byte[] rewritten = engineWrite(transformed, classes);
        classes.put(SUBJECT, rewritten);

        TestLoader loader = new TestLoader(classes);
        Class<?> type = Class.forName(SUBJECT.replace('/', '.'), true, loader);
        Class<?> calc = Class.forName(CALC.replace('/', '.'), true, loader);
        Object calcInstance = calc.getDeclaredConstructor().newInstance();
        assertEquals(10, callStaticInt(type, "staticPath", new Class<?>[]{int.class, int.class}, 5, 2));
        assertEquals(16, callStaticInt(type, "virtualPath", new Class<?>[]{calc, int.class}, calcInstance, 4));
        assertEquals("9", callStatic(type, "exceptionPath", new Class<?>[]{calc, int.class}, calcInstance, 3));
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

    private static Map<String, byte[]> classes(byte[] subject) {
        Map<String, byte[]> map = new LinkedHashMap<>();
        map.put(MATH, WrapFixtures.mathApi());
        map.put(CALC, WrapFixtures.calc());
        map.put(SUBJECT, subject);
        return map;
    }

    private static boolean callsWrapper(MethodNode method) {
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof MethodInsnNode call && call.name.startsWith("chimera$invoke$")) {
                return true;
            }
        }
        return false;
    }

    private static boolean callsOwner(MethodNode method, String owner) {
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof MethodInsnNode call && owner.equals(call.owner)) {
                return true;
            }
        }
        return false;
    }

    private static List<MethodNode> wrapperMethods(byte[] bytes) {
        List<MethodNode> wrappers = new ArrayList<>();
        for (MethodNode method : read(bytes).methods) {
            if (method.name.startsWith("chimera$invoke$")) {
                wrappers.add(method);
            }
        }
        return wrappers;
    }

    private static MethodNode find(ClassNode node, String name) {
        for (MethodNode method : node.methods) {
            if (name.equals(method.name)) {
                return method;
            }
        }
        throw new AssertionError("method not found: " + name);
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

    private static int callStaticInt(Class<?> type, String name, Class<?>[] types, Object... args)
            throws Exception {
        return ((Number) callStatic(type, name, types, args)).intValue();
    }

    private static long callStaticLong(Class<?> type, String name, Class<?>[] types, Object... args)
            throws Exception {
        return ((Number) callStatic(type, name, types, args)).longValue();
    }

    private static double callStaticDouble(Class<?> type, String name, Class<?>[] types, Object... args)
            throws Exception {
        return ((Number) callStatic(type, name, types, args)).doubleValue();
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
            super(InvokeWrapperTest.class.getClassLoader());
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
