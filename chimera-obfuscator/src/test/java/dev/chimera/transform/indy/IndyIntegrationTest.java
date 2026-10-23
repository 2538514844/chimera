package dev.chimera.transform.indy;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.LocalVariableNode;
import org.objectweb.asm.util.CheckClassAdapter;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

import static dev.chimera.transform.indy.IndyTestSamples.BRIDGE_SUBJECT;
import static dev.chimera.transform.indy.IndyTestSamples.CALC;
import static dev.chimera.transform.indy.IndyTestSamples.CALC_API;
import static dev.chimera.transform.indy.IndyTestSamples.MATH;
import static dev.chimera.transform.indy.IndyTestSamples.SUBJECT;

/**
 * M10 completion: {@link IndyIntegration#prepare} produces rewritten classes + a decodable CHMI
 * member table + aggregated statistics, Mixin classes are preserved byte-for-byte, and the
 * aggressive option rewrites eligible calls inside initializers and invokespecial sites.
 */
public class IndyIntegrationTest {

    private static final int ITERATIONS = 10_000;
    private final AtomicInteger hookCalls = new AtomicInteger();

    @BeforeEach
    void reset() {
        MemberIdRegistry.clearForTests();
        ChimeraBootstrap.installCheckHook(CheckHook.DENY);
        hookCalls.set(0);
    }

    @Test
    void aggressivePrepareRewritesInitializerAndSpecialSitesAndRoundTripsMemberTable() throws Exception {
        Map<String, byte[]> originals = IndyTestSamples.originalClasses();
        IndyIntegration.Result result = IndyIntegration.prepare(originals, IndyIntegration.Options.AGGRESSIVE);
        IndyDispatchTransformer.Stats stats = result.stats();

        // Aggregated over all four fixture classes:
        // MathOps ctor 1 + Calc ctor 1 + Calc.make 1 + Subject 12 = 15.
        assertEquals(15, stats.invokeSites());
        assertEquals(9, stats.rewritten(), "conservative 6 + init 1 + clinit 1 + special 1");
        assertEquals(6, stats.skipped());
        assertEquals(6, stats.rewrittenStatic());
        assertEquals(1, stats.rewrittenVirtual());
        assertEquals(1, stats.rewrittenInterface());
        assertEquals(1, stats.rewrittenSpecial());
        assertEquals(5, stats.skipCount(IndyDispatchTransformer.SkipReason.CONSTRUCTOR_CALL),
                "Object.<init> x3 + Calc.<init> in Calc.make and Subject.ctorPath");
        assertEquals(1, stats.skipCount(IndyDispatchTransformer.SkipReason.REFLECTION_SENSITIVE));
        assertEquals(0, stats.skipCount(IndyDispatchTransformer.SkipReason.METHOD_INIT));
        assertEquals(0, stats.skipCount(IndyDispatchTransformer.SkipReason.METHOD_CLINIT));
        assertEquals(0, stats.skipCount(IndyDispatchTransformer.SkipReason.SPECIAL_CALL));

        assertEquals(6, result.memberEntries(), "MathOps.add/mul, Calc.twice, CalcApi.twice, Subject.staticPath, Object.toString");
        assertEquals(5, result.classEntries(), "MathOps, Calc, CalcApi, Subject, java/lang/Object");
        assertEquals(0, result.preservedMixinClasses());
        assertFalse(java.util.Arrays.equals(originals.get(SUBJECT), result.classes().get(SUBJECT)));

        // Member table header is inspectable and decodes into a fresh registry.
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(result.memberTable()))) {
            assertEquals(MemberIdRegistry.MEMBER_TABLE_MAGIC, in.readInt());
            assertEquals(MemberIdRegistry.MEMBER_TABLE_VERSION, in.readInt());
            assertEquals(11, in.readInt(), "5 class entries + 6 member entries");
        }

        TestByteLoader loader = new TestByteLoader(result.classes(), getClass().getClassLoader());
        MemberIdRegistry.loadMemberTable(result.memberTable(), loader);
        assertTrue(MemberIdRegistry.registeredClasses() >= 5);
        assertTrue(MemberIdRegistry.registeredMembers() >= 6);

        ChimeraBootstrap.installCheckHook(request -> {
            hookCalls.incrementAndGet();
            return true;
        });

        // <clinit> itself is now rewritten and links during class initialization.
        Class<?> subject = Class.forName(SUBJECT.replace('/', '.'), true, loader);
        Class<?> calc = Class.forName(CALC.replace('/', '.'), true, loader);
        Class<?> api = Class.forName(CALC_API.replace('/', '.'), true, loader);

        // Reference implementation for differential checks.
        Map<String, byte[]> originalMap = new LinkedHashMap<>(originals);
        TestByteLoader originalLoader = new TestByteLoader(originalMap, getClass().getClassLoader());
        Class<?> originalSubject = Class.forName(SUBJECT.replace('/', '.'), true, originalLoader);
        Class<?> originalCalc = Class.forName(CALC.replace('/', '.'), true, originalLoader);
        Class<?> originalApi = Class.forName(CALC_API.replace('/', '.'), true, originalLoader);
        Object originalCalcInstance = originalCalc.getDeclaredConstructor().newInstance();
        Object originalSubjectInstance = originalSubject.getDeclaredConstructor().newInstance();
        Object calcInstance = calc.getDeclaredConstructor().newInstance();
        Object subjectInstance = subject.getDeclaredConstructor().newInstance();

        // <clinit> + <init> already linked while initializing/instantiating Subject.
        assertEquals(2, hookCalls.get(), "initializer links only at this point");
        assertNotNull(subject.getMethod("superPath").invoke(subjectInstance),
                "invokespecial site must be rewritten and still behave as a super call");
        assertEquals(3, hookCalls.get());

        Random random = new Random(0x4D31355L);
        for (int i = 0; i < ITERATIONS; i++) {
            int a = random.nextInt();
            int b = random.nextInt();
            int x = random.nextInt();
            assertEquals(invokeInt(originalSubject, "staticPath", new Class<?>[]{int.class, int.class}, a, b),
                    invokeInt(subject, "staticPath", new Class<?>[]{int.class, int.class}, a, b));
            assertEquals(invokeInt(originalSubject, "ctorPath", new Class<?>[]{int.class}, x),
                    invokeInt(subject, "ctorPath", new Class<?>[]{int.class}, x));
            assertEquals(invokeInt(originalSubject, "interfacePath", new Class<?>[]{originalApi, int.class},
                            originalCalcInstance, x),
                    invokeInt(subject, "interfacePath", new Class<?>[]{api, int.class}, calcInstance, x));
            assertEquals(invokeInt(originalSubject, "selfPath", new Class<?>[]{int.class}, x),
                    invokeInt(subject, "selfPath", new Class<?>[]{int.class}, x));
            assertEquals(invokeIntOn(originalSubject, "instancePath", new Class<?>[]{int.class},
                            originalSubjectInstance, x),
                    invokeIntOn(subject, "instancePath", new Class<?>[]{int.class}, subjectInstance, x));
        }
        assertEquals(9, hookCalls.get(), "linked call sites must never re-run the check");

        StringWriter diagnostics = new StringWriter();
        CheckClassAdapter.verify(new ClassReader(result.classes().get(SUBJECT)), loader, false,
                new PrintWriter(diagnostics));
        assertEquals("", diagnostics.toString().trim(), "ASM data-flow verification must pass");
    }

    @Test
    void conservativeOptionsKeepLegacyRewriteSet() {
        Map<String, byte[]> originals = IndyTestSamples.originalClasses();
        IndyIntegration.Result result = IndyIntegration.prepare(originals, IndyIntegration.Options.CONSERVATIVE);
        IndyDispatchTransformer.Stats stats = result.stats();
        assertEquals(6, stats.rewritten());
        assertEquals(9, stats.skipped());
        assertEquals(0, stats.rewrittenSpecial());
        assertEquals(4, stats.skipCount(IndyDispatchTransformer.SkipReason.METHOD_INIT));
        assertEquals(1, stats.skipCount(IndyDispatchTransformer.SkipReason.METHOD_CLINIT));
        assertEquals(1, stats.skipCount(IndyDispatchTransformer.SkipReason.SPECIAL_CALL));
        assertEquals(5, result.memberEntries());
        assertEquals(4, result.classEntries());
    }

    @Test
    void mixinBytesArePreservedVerbatimWithSignatureAndDebugInfo() throws Exception {
        byte[] mixin = IndyTestSamples.bridgeSubject();
        ClassNode originalNode = readNode(mixin);
        assertNotNull(originalNode.signature, "fixture must carry a class Signature");
        assertNotNull(originalNode.sourceFile, "fixture must carry SourceFile");
        assertTrue(hasLineNumbers(originalNode), "fixture must carry LineNumberTable");
        assertTrue(hasLocalVariables(originalNode), "fixture must carry LocalVariableTable");

        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put(BRIDGE_SUBJECT, mixin);
        IndyIntegration.Result result = IndyIntegration.prepare(classes, IndyIntegration.Options.AGGRESSIVE);

        assertEquals(1, result.preservedMixinClasses());
        assertArrayEquals(mixin, result.classes().get(BRIDGE_SUBJECT),
                "Mixin class bytes must be preserved verbatim (Signature/debug included)");
        assertEquals(2, result.stats().invokeSites());
        assertEquals(2, result.stats().skipCount(IndyDispatchTransformer.SkipReason.MIXIN_CLASS));
        assertEquals(0, result.stats().rewritten());

        ClassNode preserved = readNode(result.classes().get(BRIDGE_SUBJECT));
        assertEquals(originalNode.signature, preserved.signature);
        assertEquals(originalNode.sourceFile, preserved.sourceFile);
        assertTrue(hasLineNumbers(preserved));
        assertTrue(hasLocalVariables(preserved));
    }

    @Test
    void memberTableRejectsMalformedInput() {
        TestByteLoader loader = new TestByteLoader(IndyTestSamples.originalClasses(), getClass().getClassLoader());
        assertThrows(IllegalArgumentException.class,
                () -> MemberIdRegistry.loadMemberTable(new byte[0], loader));
        assertThrows(IllegalArgumentException.class,
                () -> MemberIdRegistry.loadMemberTable(new byte[]{0, 0, 0, 0, 0, 0, 0, 1}, loader));
    }

    // ------------------------------------------------------------------ helpers

    private static int invokeInt(Class<?> type, String name, Class<?>[] parameterTypes,
                                 Object... args) throws Exception {
        return ((Number) type.getMethod(name, parameterTypes).invoke(null, args)).intValue();
    }

    private static int invokeIntOn(Class<?> type, String name, Class<?>[] parameterTypes,
                                   Object target, Object... args) throws Exception {
        return ((Number) type.getMethod(name, parameterTypes).invoke(target, args)).intValue();
    }

    private static ClassNode readNode(byte[] bytes) {
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return node;
    }

    private static boolean hasLineNumbers(ClassNode node) {
        for (var method : node.methods) {
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof LineNumberNode) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean hasLocalVariables(ClassNode node) {
        for (var method : node.methods) {
            if (method.localVariables != null && !method.localVariables.isEmpty()) {
                return true;
            }
        }
        return false;
    }
}
