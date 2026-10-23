package dev.chimera.runtime;

import dev.chimera.auth.NativeAuthLibrary;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * B6 post-defineHiddenClass verification:
 * <ul>
 *   <li>structural checks always run on the class the VM installed (name/nest/super/interfaces/
 *       modifiers/single static run with the exact call-site descriptor);</li>
 *   <li>byte-level verification uses JVMTI GetBytecodes via
 *       {@code nativeHiddenClassBytesMatch(Class, byte[32])}: expected is the SHA-256 of the
 *       "run" method code array (JVMTI returns method bytecode, not classfile bytes). 1 match,
 *       0 tamper, -1 unavailable (structural-only PARTIAL, never reported as a pass);</li>
 *   <li>a valid-format but different bytecode replacement is detected by the byte-code hash.</li>
 * </ul>
 *
 * <p>The runtime is loaded in an isolated classloader with its own native DLL copy, matching how
 * protected jars load it. Frida hooking is not executed here (see docs/FRIDA-STATUS.md).</p>
 */
class B6PostDefineTest {

    private static URLClassLoader runtimeLoader;
    private static Class<?> runtime;

    @BeforeAll
    static void loadIsolatedRuntime() throws Exception {
        NativeAuthLibrary.prepareIsolatedCopy();
        URL classes = ChimeraRuntime.class.getProtectionDomain().getCodeSource().getLocation();
        runtimeLoader = new URLClassLoader(new URL[]{classes}, ClassLoader.getPlatformClassLoader());
        runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true, runtimeLoader);
    }

    @AfterAll
    static void closeRuntime() throws Exception {
        if (runtimeLoader != null) runtimeLoader.close();
    }

    @Test
    void structuralValidatorAcceptsTheExpectedHiddenFragment() throws Exception {
        byte[] bytes = fragmentClass("dev/chimera/runtime/B6PostDefineTest$chimera$7",
                "run", "(I)I");
        Class<?> hidden = defineHidden(bytes);
        invokeStructuralValidator(7, B6PostDefineTest.class, hidden,
                MethodType.methodType(int.class, int.class));
    }

    @Test
    void structuralValidatorRejectsAReplacementWithADifferentShape() throws Exception {
        byte[] bytes = fragmentClass("dev/chimera/runtime/B6PostDefineTest$chimera$8",
                "notRun", "(I)I");
        Class<?> hidden = defineHidden(bytes);
        InvocationTargetException failure = assertThrows(InvocationTargetException.class,
                () -> invokeStructuralValidator(8, B6PostDefineTest.class, hidden,
                        MethodType.methodType(int.class, int.class)));
        assertTrue(failure.getCause() instanceof IllegalStateException,
                "structural mismatch must fail closed, got " + failure.getCause());
    }

    @Test
    void nativeJvmtiBytecodeHashDetectsSameShapeReplacement() throws Exception {
        assertTrue((Boolean) runtime.getMethod("nativeAuthAvailable").invoke(null),
                "native auth DLL must be loaded in the isolated runtime");
        assertEquals(1, ((Integer) runtime.getMethod("nativeJvmtiAvailable").invoke(null)).intValue(),
                "JVMTI GetBytecodes must be available (no -agentpath required)");

        byte[] original = fragmentClass("dev/chimera/runtime/B6PostDefineTest$chimera$9",
                "run", "(I)I");
        Class<?> hidden = defineHidden(original);
        byte[] expected = expectedRunBytecodeHash(original);
        assertEquals(1, ((Integer) nativeMatch(hidden, expected)).intValue(),
                "actual method bytecode must match the build-time run-code hash");

        byte[] wrong = expected.clone();
        wrong[0] ^= 0x01;
        assertEquals(0, ((Integer) nativeMatch(hidden, wrong)).intValue(),
                "a same-shape bytecode replacement must be detected as a mismatch");
    }

    // ------------------------------------------------------------------ helpers

    private static Class<?> defineHidden(byte[] bytes) throws Exception {
        return MethodHandles.lookup().defineHiddenClass(bytes, true,
                MethodHandles.Lookup.ClassOption.NESTMATE).lookupClass();
    }

    private static void invokeStructuralValidator(int id, Class<?> owner, Class<?> hidden,
                                                  MethodType type) throws Exception {
        Method validator = runtime.getDeclaredMethod("verifyDefinedChunk",
                int.class, Class.class, Class.class, MethodType.class);
        validator.setAccessible(true);
        validator.invoke(null, id, owner, hidden, type);
    }

    private static byte[] expectedRunBytecodeHash(byte[] classBytes) throws Exception {
        Method hash = runtime.getDeclaredMethod("runBytecodeSha256", byte[].class);
        hash.setAccessible(true);
        return (byte[]) hash.invoke(null, classBytes);
    }

    private static Object nativeMatch(Class<?> hidden, byte[] expected) throws Exception {
        Method match = runtime.getMethod("nativeHiddenClassBytesMatch", Class.class, byte[].class);
        return match.invoke(null, hidden, expected);
    }

    private static byte[] fragmentClass(String name, String methodName, String descriptor) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER | Opcodes.ACC_SYNTHETIC,
                name, null, "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                methodName, descriptor, null, null);
        method.visitCode();
        if ("(I)I".equals(descriptor)) {
            method.visitVarInsn(Opcodes.ILOAD, 0);
            method.visitInsn(Opcodes.IRETURN);
            method.visitMaxs(1, 1);
        } else {
            method.visitInsn(Opcodes.RETURN);
            method.visitMaxs(0, 0);
        }
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }
}
