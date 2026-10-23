package dev.chimera.transform.indy;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * M10: signature-compatible member-id registry ({@code a/b/c/d}) plus deterministic id derivation
 * and cache/counter behaviour.
 */
public class MemberIdRegistryTest {

    @BeforeEach
    void reset() {
        MemberIdRegistry.clearForTests();
    }

    @AfterEach
    void cleanup() {
        MemberIdRegistry.clearForTests();
    }

    @Test
    void afCompatibleSignaturesAreExposed() throws Exception {
        Method a = MemberIdRegistry.class.getMethod("a", long.class, long.class);
        Method b = MemberIdRegistry.class.getMethod("b", long.class, long.class);
        Method c = MemberIdRegistry.class.getMethod("c", long.class, long.class);
        Method d = MemberIdRegistry.class.getMethod("d", long.class, long.class);

        assertEquals(int.class, a.getReturnType(), "a(JJ)I");
        assertEquals(Class.class, b.getReturnType(), "b(JJ)Class");
        assertEquals(Field.class, c.getReturnType(), "c(JJ)Field");
        assertEquals(Method.class, d.getReturnType(), "d(JJ)Method");
        for (Method method : new Method[]{a, b, c, d}) {
            assertTrue(Modifier.isStatic(method.getModifiers()));
            assertArrayEquals(new Class<?>[]{long.class, long.class}, method.getParameterTypes());
        }
    }

    @Test
    void registerAndResolveClassFieldMethodWithFallbacks() throws Exception {
        Class<?> math = loadMath();
        Field seed = math.getField("SEED");
        Method add = math.getMethod("add", int.class, int.class);

        MemberIdRegistry.registerClass(math);
        MemberIdRegistry.registerField(math, "SEED");
        MemberIdRegistry.registerMethod(math, "add", int.class, int.class);

        long classId = MemberIdRegistry.classId(IndyTestSamples.MATH);
        long fieldId = MemberIdRegistry.memberId(IndyTestSamples.MATH, "SEED",
                org.objectweb.asm.Type.getDescriptor(seed.getType()));
        long methodId = MemberIdRegistry.memberId(IndyTestSamples.MATH, "add",
                org.objectweb.asm.Type.getMethodDescriptor(add));

        assertSame(math, MemberIdRegistry.b(classId, methodId));
        Field resolvedField = MemberIdRegistry.c(classId, fieldId);
        assertNotNull(resolvedField);
        assertEquals(seed.getName(), resolvedField.getName());
        assertEquals(seed.getDeclaringClass(), resolvedField.getDeclaringClass());
        Method resolvedMethod = MemberIdRegistry.d(classId, methodId);
        assertNotNull(resolvedMethod);
        assertEquals(add.getName(), resolvedMethod.getName());
        assertEquals(add.getDeclaringClass(), resolvedMethod.getDeclaringClass());
        assertArrayEquals(add.getParameterTypes(), resolvedMethod.getParameterTypes());
        assertEquals(MemberIdRegistry.MEMBER_FIELD, MemberIdRegistry.a(classId, fieldId));
        assertEquals(MemberIdRegistry.MEMBER_METHOD, MemberIdRegistry.a(classId, methodId));
        assertTrue(MemberIdRegistry.isStatic(classId, methodId));

        // Unknown ids: fail-soft lookups (the bootstrap turns null into BootstrapMethodError).
        long unknown = 0x1234L;
        assertEquals(0, MemberIdRegistry.a(classId, unknown));
        assertNull(MemberIdRegistry.c(classId, unknown));
        assertNull(MemberIdRegistry.d(classId, unknown));
        assertNull(MemberIdRegistry.b(unknown, methodId));
        assertTrue(MemberIdRegistry.misses() >= 4, "unknown lookups must be counted");

        assertEquals(2, MemberIdRegistry.registeredMembers());
        assertEquals(1, MemberIdRegistry.registeredClasses());
    }

    @Test
    void idsAreDeterministicAndDistinct() {
        long classA = MemberIdRegistry.classId("sample/MathOps");
        long classB = MemberIdRegistry.classId("sample/MathOps");
        long classC = MemberIdRegistry.classId("sample/Calc");
        assertEquals(classA, classB, "class ids must be deterministic across calls");
        assertNotEquals(classA, classC);

        long add = MemberIdRegistry.memberId("sample/MathOps", "add", "(II)I");
        long addAgain = MemberIdRegistry.memberId("sample/MathOps", "add", "(II)I");
        long mul = MemberIdRegistry.memberId("sample/MathOps", "mul", "(II)I");
        assertEquals(add, addAgain);
        assertNotEquals(add, mul, "owner/name/desc must all contribute to the member id");
        assertNotEquals(add, MemberIdRegistry.memberId("sample/MathOps", "add", "(JJ)J"));
    }

    @Test
    void clearResetsRegistrationsAndCounters() throws Exception {
        Class<?> math = loadMath();
        MemberIdRegistry.registerClass(math);
        MemberIdRegistry.registerMethod(math, "add", int.class, int.class);
        long classId = MemberIdRegistry.classId(IndyTestSamples.MATH);
        long methodId = MemberIdRegistry.memberId(IndyTestSamples.MATH, "add",
                "(II)I");
        assertSame(math, MemberIdRegistry.b(classId, methodId));
        assertNotNull(MemberIdRegistry.d(classId, methodId));
        assertTrue(MemberIdRegistry.classLookups() > 0);
        assertTrue(MemberIdRegistry.memberLookups() > 0);

        MemberIdRegistry.clearForTests();
        assertEquals(0, MemberIdRegistry.registeredClasses());
        assertEquals(0, MemberIdRegistry.registeredMembers());
        assertEquals(0, MemberIdRegistry.classLookups());
        assertEquals(0, MemberIdRegistry.memberLookups());
        assertEquals(0, MemberIdRegistry.misses());
        assertNull(MemberIdRegistry.b(classId, methodId));
    }

    private static Class<?> loadMath() throws Exception {
        Map<String, byte[]> classes = IndyTestSamples.originalClasses();
        TestByteLoader loader = new TestByteLoader(classes, MemberIdRegistryTest.class.getClassLoader());
        return Class.forName(IndyTestSamples.MATH.replace('/', '.'), true, loader);
    }
}
