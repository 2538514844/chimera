package dev.chimera.runtime;

import dev.chimera.auth.NativeAuthLibrary;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * C7: the native surface must fail <b>closed</b> when there is no authorized session.
 *
 * <p>These paths are what an attacker reaches first, and none of them were covered by a test before
 * - the previous suite exercised the Java wrappers (which short-circuit on {@code nativeAuthLoaded})
 * and the happy path on a real machine, but never "what does native return with no handle".</p>
 *
 * <p>Asserted here: no class key, no decryption, no manifest key without a session; the hardware id
 * is a stable 64-hex value; the QQ hint is empty or a plausible number; and a dev build reports
 * "no VMProtect SDK" rather than pretending the image CRC passed. The per-class gate no longer
 * returns anything at all - its denial path is a native {@code _Exit(4)}, which a dev DLL must not
 * take.</p>
 */
class NativeFailClosedTest {

    private static boolean nativeReady;

    @BeforeAll
    static void loadNative() {
        try {
            System.load(NativeAuthLibrary.prepare());
            nativeReady = true;
        } catch (Throwable alreadyLoadedOrMissing) {
            // Another test in this JVM may have bound the library already; probe below decides.
            nativeReady = probe();
        }
    }

    private static boolean probe() {
        try {
            call("nativeDevBuild");
            return true;
        } catch (Throwable unavailable) {
            return false;
        }
    }

    @Test
    void gateCheckIsANoOpInDevBuild() throws Exception {
        Assumptions.assumeTrue(nativeReady, "native DLL unavailable");
        // A2 (red team round 3 fix): the gate no longer returns a token. In a release DLL it
        // terminates the process when there is no live handle; a dev DLL must be a no-op, otherwise
        // every unit test and every unlicensed dev run would die on the first gated <clinit>.
        assertNull(call("nativeGateCheck", new Class<?>[]{int.class}, 7),
                "void gate check returns nothing - there is no verdict for Java to read");
        assertNull(call("nativeGateCheck", new Class<?>[]{int.class}, 0));
    }

    @Test
    void decryptReturnsNothingWithoutHandle() throws Exception {
        Assumptions.assumeTrue(nativeReady, "native DLL unavailable");
        byte[] blob = new byte[128];
        byte[] name = "a/B".getBytes(StandardCharsets.UTF_8);
        Object result = call("nativeDecryptClass",
                new Class<?>[]{long.class, byte[].class, byte[].class}, 0L, blob, name);
        assertNotNull(result);
        assertEquals(0, ((byte[]) result).length, "no handle -> empty plaintext, never garbage");
    }

    @Test
    void decryptRejectsHandleZeroEvenForAWellFormedHeader() throws Exception {
        Assumptions.assumeTrue(nativeReady, "native DLL unavailable");
        byte[] blob = new byte[128];
        byte[] magic = {'C', 'H', 'E', 'N', 'C', '1', 0};
        System.arraycopy(magic, 0, blob, 0, magic.length);
        blob[7] = 1;  // version 1, so the header check passes and the handle check decides
        Object result = call("nativeDecryptClass",
                new Class<?>[]{long.class, byte[].class, byte[].class}, 0L, blob,
                "a/B".getBytes(StandardCharsets.UTF_8));
        assertEquals(0, ((byte[]) result).length);
    }

    @Test
    void hwidIsStableLowercaseHex() throws Exception {
        Assumptions.assumeTrue(nativeReady, "native DLL unavailable");
        String first = (String) call("nativeHwid");
        String second = (String) call("nativeHwid");
        assertNotNull(first);
        assertTrue(first.matches("[0-9a-f]{64}"),
                "hardware id must be 64 lowercase hex chars, got: " + first);
        assertEquals(first, second, "the hardware id must not change between calls");
    }

    @Test
    void qqHintIsEmptyOrPlausible() throws Exception {
        Assumptions.assumeTrue(nativeReady, "native DLL unavailable");
        String qq = (String) call("nativeQqHint");
        assertNotNull(qq);
        assertTrue(qq.isEmpty() || qq.matches("\\d{5,11}"),
                "QQ hint must be empty or 5-11 digits, got: " + qq);
    }

    @Test
    void devBuildReportsNoVmpSdk() throws Exception {
        Assumptions.assumeTrue(nativeReady, "native DLL unavailable");
        assertEquals(1, call("nativeDevBuild"), "this is the dev DLL");
        assertEquals(-1, call("nativeVmpImageCrc"),
                "dev builds have no VMProtect SDK, so the verdict must be -1, not a fake 1");
    }

    @Test
    void manifestKeyIsNotPinnedInDevBuilds() throws Exception {
        Assumptions.assumeTrue(nativeReady, "native DLL unavailable");
        assertEquals(Boolean.FALSE, call("nativeManifestKeyPinned"),
                "dev DLLs are built without -DCHIMERA_MANIFEST_KEY_HEX");
    }

    private static Object call(String name, Class<?>[] types, Object... args) throws Exception {
        Method method = ChimeraRuntime.class.getDeclaredMethod(name, types);
        method.setAccessible(true);
        return method.invoke(null, args);
    }

    private static Object call(String name) throws Exception {
        return call(name, new Class<?>[0]);
    }
}
