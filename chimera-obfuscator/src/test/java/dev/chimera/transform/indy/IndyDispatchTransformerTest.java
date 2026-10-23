package dev.chimera.transform.indy;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.util.CheckClassAdapter;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

import static dev.chimera.transform.indy.IndyTestSamples.CALC;
import static dev.chimera.transform.indy.IndyTestSamples.CALC_API;
import static dev.chimera.transform.indy.IndyTestSamples.MATH;
import static dev.chimera.transform.indy.IndyTestSamples.SUBJECT;

/**
 * M10 acceptance: rewrite -> link -> execute with random inputs, compared against the untransformed
 * implementation; skip statistics; one-time link resolution/caching; ASM validation.
 */
public class IndyDispatchTransformerTest {

    private static final int ITERATIONS = 10_000;

    private final AtomicInteger hookCalls = new AtomicInteger();

    @BeforeEach
    void resetGlobalState() {
        MemberIdRegistry.clearForTests();
        ChimeraBootstrap.installCheckHook(CheckHook.DENY);
        hookCalls.set(0);
    }

    @Test
    void rewritesCallSitesAndMatchesOriginalSemanticsFor10kRandomInputs() throws Exception {
        Map<String, byte[]> originals = IndyTestSamples.originalClasses();

        IndyDispatchTransformer.TransformResult transformed =
                IndyDispatchTransformer.transformClass(originals.get(SUBJECT));
        IndyDispatchTransformer.Stats stats = transformed.stats();

        assertEquals(12, stats.invokeSites(), "every invoke site must be accounted for");
        assertEquals(6, stats.rewritten(), "static/virtual/interface sites");
        assertEquals(2, stats.skipCount(IndyDispatchTransformer.SkipReason.METHOD_INIT));
        assertEquals(1, stats.skipCount(IndyDispatchTransformer.SkipReason.METHOD_CLINIT));
        assertEquals(1, stats.skipCount(IndyDispatchTransformer.SkipReason.CONSTRUCTOR_CALL));
        assertEquals(1, stats.skipCount(IndyDispatchTransformer.SkipReason.SPECIAL_CALL));
        assertEquals(1, stats.skipCount(IndyDispatchTransformer.SkipReason.REFLECTION_SENSITIVE));
        assertEquals(6, stats.skipped());

        ClassNode rewrittenNode = new ClassNode();
        new ClassReader(transformed.bytes()).accept(rewrittenNode, 0);
        assertEquals(6, countInvokeDynamics(rewrittenNode));
        // The only eligible opcode left is the deliberately skipped Class.forName call.
        assertEquals(1, countRemainingEligibleInvokes(rewrittenNode));
        // Structural validation of the transformed class file.
        new ClassReader(transformed.bytes())
                .accept(new CheckClassAdapter(new ClassWriter(0), false), 0);

        // Original implementation (reference results).
        TestByteLoader originalLoader = new TestByteLoader(originals, getClass().getClassLoader());
        Class<?> originalSubject = Class.forName(SUBJECT.replace('/', '.'), true, originalLoader);
        Class<?> originalCalc = Class.forName(CALC.replace('/', '.'), true, originalLoader);
        Class<?> originalApi = Class.forName(CALC_API.replace('/', '.'), true, originalLoader);

        // Rewritten implementation, dependencies unchanged.
        Map<String, byte[]> rewritten = new LinkedHashMap<>(originals);
        rewritten.put(SUBJECT, transformed.bytes());
        TestByteLoader rewrittenLoader = new TestByteLoader(rewritten, getClass().getClassLoader());
        Class<?> subject = Class.forName(SUBJECT.replace('/', '.'), true, rewrittenLoader);
        Class<?> math = Class.forName(MATH.replace('/', '.'), true, rewrittenLoader);
        Class<?> calc = Class.forName(CALC.replace('/', '.'), true, rewrittenLoader);
        Class<?> api = Class.forName(CALC_API.replace('/', '.'), true, rewrittenLoader);

        registerRewrittenMembers(math, calc, api, subject);
        ChimeraBootstrap.installCheckHook(request -> {
            hookCalls.incrementAndGet();
            return true;
        });

        // First executions link every rewritten call site exactly once.
        invokeInt(subject, "staticPath", new Class<?>[]{int.class, int.class}, 1, 2);
        invokeInt(subject, "ctorPath", new Class<?>[]{int.class}, 5);
        Object calcInstance = calc.getDeclaredConstructor().newInstance();
        invokeInt(subject, "interfacePath", new Class<?>[]{api, int.class}, calcInstance, 6);
        invokeInt(subject, "selfPath", new Class<?>[]{int.class}, 7);
        Object subjectInstance = subject.getDeclaredConstructor().newInstance();
        invokeIntOn(subject, "instancePath", new Class<?>[]{int.class}, subjectInstance, 8);
        Object superResult = subject.getMethod("superPath").invoke(subjectInstance);
        assertNotNull(superResult);

        assertEquals(6, hookCalls.get(), "CheckHook must run once per rewritten call site");
        assertEquals(6, MemberIdRegistry.classLookups(), "class resolution must happen once per call site");
        assertEquals(6, MemberIdRegistry.memberLookups(), "member resolution must happen once per call site");

        Random random = new Random(0x4D3130L);
        Object originalCalcInstance = originalCalc.getDeclaredConstructor().newInstance();
        Object originalSubjectInstance = originalSubject.getDeclaredConstructor().newInstance();
        for (int i = 0; i < ITERATIONS; i++) {
            int a = random.nextInt();
            int b = random.nextInt();
            int x = random.nextInt();
            assertEquals(
                    invokeInt(originalSubject, "staticPath", new Class<?>[]{int.class, int.class}, a, b),
                    invokeInt(subject, "staticPath", new Class<?>[]{int.class, int.class}, a, b));
            assertEquals(
                    invokeInt(originalSubject, "ctorPath", new Class<?>[]{int.class}, x),
                    invokeInt(subject, "ctorPath", new Class<?>[]{int.class}, x));
            assertEquals(
                    invokeInt(originalSubject, "interfacePath", new Class<?>[]{originalApi, int.class},
                            originalCalcInstance, x),
                    invokeInt(subject, "interfacePath", new Class<?>[]{api, int.class}, calcInstance, x));
            assertEquals(
                    invokeInt(originalSubject, "selfPath", new Class<?>[]{int.class}, x),
                    invokeInt(subject, "selfPath", new Class<?>[]{int.class}, x));
            assertEquals(
                    invokeIntOn(originalSubject, "instancePath", new Class<?>[]{int.class},
                            originalSubjectInstance, x),
                    invokeIntOn(subject, "instancePath", new Class<?>[]{int.class}, subjectInstance, x));
        }

        assertEquals(6, hookCalls.get(), "linked call sites must never re-run the check");
        assertEquals(6, MemberIdRegistry.classLookups(), "the bootstrap must not re-resolve per call");
        assertEquals(6, MemberIdRegistry.memberLookups());

        // Data-flow verification with the real loader (resolves hierarchy).
        StringWriter diagnostics = new StringWriter();
        CheckClassAdapter.verify(new ClassReader(transformed.bytes()), rewrittenLoader, false,
                new PrintWriter(diagnostics));
        assertEquals("", diagnostics.toString().trim(), "ASM data-flow verification must pass");
    }

    @Test
    void deniedHookFailsClosedWithoutExecutingTheTarget() throws Exception {
        Map<String, byte[]> originals = IndyTestSamples.originalClasses();
        byte[] rewrittenSubject = IndyDispatchTransformer.transformClass(originals.get(SUBJECT)).bytes();
        Map<String, byte[]> rewritten = new LinkedHashMap<>(originals);
        rewritten.put(SUBJECT, rewrittenSubject);
        TestByteLoader loader = new TestByteLoader(rewritten, getClass().getClassLoader());
        Class<?> subject = Class.forName(SUBJECT.replace('/', '.'), true, loader);
        registerRewrittenMembers(
                Class.forName(MATH.replace('/', '.'), true, loader),
                Class.forName(CALC.replace('/', '.'), true, loader),
                Class.forName(CALC_API.replace('/', '.'), true, loader),
                subject);

        ChimeraBootstrap.installCheckHook(CheckHook.DENY);
        InvocationTargetException thrown = assertThrows(InvocationTargetException.class, () ->
                subject.getMethod("staticPath", int.class, int.class).invoke(null, 1, 2));
        assertTrue(hasBootstrapMethodError(thrown.getCause()),
                "denied link must throw BootstrapMethodError, got " + thrown.getCause());

        // Default hook is a real session check, never a fabricated allow.
        ChimeraBootstrap.installCheckHook(null);
        assertThrows(InvocationTargetException.class, () ->
                subject.getMethod("staticPath", int.class, int.class).invoke(null, 1, 2));
    }

    @Test
    void mixinClassIsFullySkippedAndValidated() throws Exception {
        byte[] mixin = IndyTestSamples.bridgeSubject();
        assertTrue(IndyDispatchTransformer.isMixinClass(readNode(mixin)));

        IndyDispatchTransformer.TransformResult result = IndyDispatchTransformer.transformClass(mixin);
        IndyDispatchTransformer.Stats stats = result.stats();
        assertEquals(2, stats.invokeSites());
        assertEquals(0, stats.rewritten());
        assertEquals(2, stats.skipCount(IndyDispatchTransformer.SkipReason.MIXIN_CLASS));
        ClassNode node = readNode(result.bytes());
        assertEquals(0, countInvokeDynamics(node));
        new ClassReader(result.bytes()).accept(new CheckClassAdapter(new ClassWriter(0), false), 0);
    }

    // ------------------------------------------------------------------ helpers

    private static void registerRewrittenMembers(Class<?> math, Class<?> calc, Class<?> api,
                                                 Class<?> subject) {
        MemberIdRegistry.registerClass(math);
        MemberIdRegistry.registerClass(calc);
        MemberIdRegistry.registerClass(api);
        MemberIdRegistry.registerClass(subject);
        MemberIdRegistry.registerMethod(math, "add", int.class, int.class);
        MemberIdRegistry.registerMethod(math, "mul", int.class, int.class);
        MemberIdRegistry.registerMethod(calc, "twice", int.class);
        MemberIdRegistry.registerMethod(api, "twice", int.class);
        MemberIdRegistry.registerMethod(subject, "staticPath", int.class, int.class);
    }

    private static int invokeInt(Class<?> type, String name, Class<?>[] parameterTypes,
                                 Object... args) throws Exception {
        Method method = type.getMethod(name, parameterTypes);
        return ((Number) method.invoke(null, args)).intValue();
    }

    private static int invokeIntOn(Class<?> type, String name, Class<?>[] parameterTypes,
                                   Object target, Object... args) throws Exception {
        Method method = type.getMethod(name, parameterTypes);
        return ((Number) method.invoke(target, args)).intValue();
    }

    private static ClassNode readNode(byte[] bytes) {
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return node;
    }

    private static int countInvokeDynamics(ClassNode node) {
        int count = 0;
        for (var method : node.methods) {
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof InvokeDynamicInsnNode) {
                    count++;
                }
            }
        }
        return count;
    }

    private static int countRemainingEligibleInvokes(ClassNode node) {
        int count = 0;
        for (var method : node.methods) {
            if ("<init>".equals(method.name) || "<clinit>".equals(method.name)) {
                continue;
            }
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof MethodInsnNode call) {
                    int opcode = call.getOpcode();
                    boolean rewritable = opcode == Opcodes.INVOKESTATIC
                            || opcode == Opcodes.INVOKEVIRTUAL
                            || opcode == Opcodes.INVOKEINTERFACE;
                    if (rewritable) {
                        // Only reflection/self-package/special skips may remain; none in Subject.
                        count++;
                    }
                }
            }
        }
        return count;
    }

    private static boolean hasBootstrapMethodError(Throwable throwable) {
        Throwable current = throwable;
        while (current != null) {
            if (current instanceof BootstrapMethodError) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }
}
