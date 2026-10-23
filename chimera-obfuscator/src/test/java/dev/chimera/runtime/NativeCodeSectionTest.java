package dev.chimera.runtime;

import dev.chimera.auth.NativeAuthLibrary;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * B3-1 (KI-03): proves the native auth module hashes its own PE {@code .text} section in
 * {@code JNI_OnLoad} and detects a classic inline hook.
 *
 * <p>The tamper is a real self-modification of the code page: the dev-only native helper changes
 * the first 5 bytes of {@code aes_gcm_decrypt} with {@code VirtualProtect} (0xCC INT3, or
 * 0xE9 + rel32 JMP), the SHA-256 baseline and protected-prologue checks detect it, hot JNI entries
 * poison their results, and the original bytes are restored afterwards. The helper exists only in
 * the dev DLL ({@code -DCHIMERA_DEV_BUILD}); release DLLs compile it out.</p>
 */
class NativeCodeSectionTest {
    private static final long PROBE_HANDLE = 0x1122334455667788L;

    /** Dev-DLL-only QA hooks implemented in chimera_auth.cpp (never exported by release builds). */
    private static native int nativeCorruptCodeForTest(int pattern);

    private static native int nativeRestoreCodeForTest();

    @BeforeAll
    static void loadNative() {
        NativeAuthLibrary.prepareIsolatedCopy();
        assertTrue(ChimeraRuntime.nativeAuthAvailable(), "native auth library must load");
        Assumptions.assumeTrue(ChimeraRuntime.isDevNativeBuild(),
                "B3-1 tamper hooks live in the dev DLL only; run the Gradle test task");
    }

    @AfterEach
    void restoreCodeBestEffort() {
        try {
            nativeRestoreCodeForTest();
        } catch (Throwable ignored) {
            // test bodies restore in finally; this is a safety net for a failed assertion
        }
    }

    @Test
    void intactCodeSectionIsReported() {
        assertEquals(1, ChimeraRuntime.nativeCodeSectionIntact(),
                "JNI_OnLoad baseline must match the unmodified .text section");
        assertTrue(ChimeraRuntime.codeSectionIntact());
    }

    @Test
    void int3PatchIsDetectedAndPoisonsNativeResults() {
        assertEquals(1, ChimeraRuntime.nativeCodeSectionIntact());
        long before = ChimeraRuntime.nativeCheckHandle(PROBE_HANDLE);
        assertEquals(1, nativeCorruptCodeForTest(0xCC),
                "VirtualProtect + 0xCC write must succeed (dev DLL)");
        try {
            assertEquals(0, ChimeraRuntime.nativeCodeSectionIntact(),
                    "0xCC prologue patch must invalidate the .text baseline");
            assertFalse(ChimeraRuntime.codeSectionIntact());
            long tampered = ChimeraRuntime.nativeCheckHandle(PROBE_HANDLE);
            assertNotEquals(before, tampered,
                    "nativeCheckHandle must switch to the B3-1 poison shape while patched");
            byte[] canary = ChimeraRuntime.nativeCompute(1L, new byte[]{(byte) 5});
            assertNotNull(canary);
            assertEquals(8, canary.length);
            assertEquals(0L, bigEndianLong(canary), "canary must fail closed (0) while patched");
        } finally {
            assertEquals(1, nativeRestoreCodeForTest(), "restore must put the original bytes back");
        }
        assertEquals(1, ChimeraRuntime.nativeCodeSectionIntact(),
                "baseline must match again after the bytes are restored");
        assertTrue(ChimeraRuntime.codeSectionIntact());
    }

    @Test
    void jmpRel32PatchIsDetected() {
        assertEquals(1, nativeCorruptCodeForTest(0xE9),
                "VirtualProtect + 0xE9 write must succeed (dev DLL)");
        try {
            assertEquals(0, ChimeraRuntime.nativeCodeSectionIntact(),
                    "0xE9 JMP rel32 prologue patch must invalidate the .text baseline");
            assertFalse(ChimeraRuntime.codeSectionIntact());
        } finally {
            assertEquals(1, nativeRestoreCodeForTest());
        }
        assertEquals(1, ChimeraRuntime.nativeCodeSectionIntact());
    }

    @Test
    void restoredCodeKeepsNativeEntriesUsable() {
        assertEquals(1, nativeCorruptCodeForTest(0xCC));
        assertEquals(0, ChimeraRuntime.nativeCodeSectionIntact());
        assertEquals(1, nativeRestoreCodeForTest());
        assertEquals(1, ChimeraRuntime.nativeCodeSectionIntact());
        // No exception: invalid handles keep the same numeric/byte-array shape.
        ChimeraRuntime.nativeCheckHandle(PROBE_HANDLE);
        byte[] canary = ChimeraRuntime.nativeCompute(1L, new byte[]{(byte) 5});
        assertNotNull(canary);
        assertEquals(8, canary.length);
    }

    private static long bigEndianLong(byte[] bytes) {
        long value = 0;
        for (byte b : bytes) value = (value << 8) | (b & 0xFFL);
        return value;
    }
}
