package dev.chimera.runtime;

import dev.chimera.auth.NativeAuthLibrary;
import dev.chimera.crypto.Crypto;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * B7 step 2 native self-tests (dev DLL only):
 * CALL_NATIVE opaque table, PENDING handle + VERIFY_DECISION, B2 handle mixing,
 * forced-EVP_DigestVerify result rejection, CHIMERA_TEST_MODE baseline bypass,
 * op9 DECRYPT_DATA + SecureZeroMemory residue, and the fixed pools/arena.
 */
class NativeB7Step2Test {
    private static final int STATE_VALID = 1;
    private static final int STATE_POISON = 2;
    private static final int STATE_PENDING = 3;

    private static native long nativeInstallTestHandleForTest(byte[] contentKey, int state);

    private static native long nativeInstallTestHandleWithResourceKeyForTest(
            byte[] contentKey, byte[] resourceKey, int state);

    private static native byte[] nativeSessionConstForTest(long handle);

    private static native byte[] nativeSessionNonceForTest(long handle);

    private static native int nativeDecisionForTest(byte[] tag, long handle);

    private static native byte[] nativeCallNativeForTest(int opaqueIndex, byte[] payload);

    private static native int nativeOpaqueIndexForTest(int which);

    private static native long nativeHandleMixForTest(long base, int verifyResult, byte[] nonce);

    private static native int nativeSecureWipeSelfTestForTest();

    private static native int nativeArenaResidueForTest(byte[] needle);

    private static native int nativeSetTestModeForTest(int mode);

    private static native int nativeTestModeForTest();

    private static native int nativeForceVerifyResultForTest(int enabled, int result);

    private static native int nativeEd25519IndependentDebugForTest(
            byte[] pub, byte[] msg, byte[] sig);

    private static native long nativeInstallTestDecisionHandleForTest(
            byte[] contentKey, byte[] transcript, byte[] signature);

    private static native int nativeForcePendingForTest(long handle);

    private static native long nativeHeapWindowBeginForTest();

    private static native int nativeHeapWindowEndForTest();

    private static native int nativeHeapWindowAllocCountForTest();

    private static native int nativeHeapWindowSelfTestForTest();

    private static native long nativeArenaSizeForTest();

    private static native int nativeCorruptCodeForTest(int pattern);

    private static native int nativeRestoreCodeForTest();

    @BeforeAll
    static void loadNative() {
        NativeAuthLibrary.prepareIsolatedCopy();
        assertTrue(ChimeraRuntime.nativeAuthAvailable(), "native auth library must load");
        Assumptions.assumeTrue(ChimeraRuntime.isDevNativeBuild(),
                "B7 native hooks live in the dev DLL only; run the Gradle test task");
    }

    @AfterEach
    void cleanupState() {
        try {
            nativeForceVerifyResultForTest(0, 0);
        } catch (Throwable ignored) {
            // dev hooks only
        }
        try {
            nativeRestoreCodeForTest();
        } catch (Throwable ignored) {
            // dev hooks only
        }
        try {
            nativeSetTestModeForTest(0);
        } catch (Throwable ignored) {
            // dev hooks only
        }
    }

    @Test
    void testModeAllowsPostLoadCodePatches() {
        assertEquals(0, nativeTestModeForTest(), "test mode is opt-in");
        assertEquals(1, nativeSetTestModeForTest(1));
        assertEquals(1, nativeCorruptCodeForTest(0xCC),
                "dev hook must be able to rewrite .text after JNI_OnLoad");
        assertEquals(1, ChimeraRuntime.nativeCodeSectionIntact(),
                "CHIMERA_TEST_MODE skips the B3-1 baseline so post-load Frida hooks are allowed");
        assertEquals(1, nativeRestoreCodeForTest());
        assertEquals(0, nativeSetTestModeForTest(0));
        assertEquals(1, ChimeraRuntime.nativeCodeSectionIntact(),
                "disabling test mode restores normal B3-1 checks");
    }

    @Test
    void opaqueTableDispatchesSha256WithoutAddresses() {
        int shaIndex = nativeOpaqueIndexForTest(2);
        assertTrue(shaIndex > 0, "opaque index must be a u16 constant, not an address");
        byte[] data = new byte[32];
        for (int i = 0; i < data.length; i++) data[i] = (byte) (i * 7 + 3);
        byte[] payload = new byte[2 + 32];
        payload[0] = 1;   // argc
        payload[1] = 3;   // retKind: raw byte[]
        System.arraycopy(data, 0, payload, 2, 32);
        byte[] out = nativeCallNativeForTest(shaIndex, payload);
        assertNotNull(out);
        assertArrayEquals(Crypto.sha256(data), out,
                "table index 2 must compute SHA-256 of the fixed 32B slot");
        assertArrayEquals(new byte[0], nativeCallNativeForTest(0x1111, payload),
                "unknown opaque index must fail closed");
    }

    @Test
    void pendingHandleIsPromotedByVerifyDecision() {
        byte[] key = randomBytes(32);
        long handle = nativeInstallTestHandleForTest(key, STATE_PENDING);
        assertNotEquals(0L, handle);
        assertEquals(0L, canary(handle), "PENDING must not pass the canary");

        byte[] nonce = nativeSessionNonceForTest(handle);
        byte[] sessionConst = nativeSessionConstForTest(handle);
        assertNotNull(nonce);
        assertNotNull(sessionConst);
        assertEquals(32, nonce.length);
        assertEquals(32, sessionConst.length);
        byte[] tag = verifyTag(1L, nonce, sessionConst);
        assertEquals(STATE_VALID, nativeDecisionForTest(tag, handle),
                "matching tag must promote PENDING -> VALID");
        assertEquals(1L, canary(handle));

        long fresh = nativeInstallTestHandleForTest(key, STATE_PENDING);
        byte[] wrong = tag.clone();
        wrong[0] ^= 0x01;
        assertEquals(STATE_POISON, nativeDecisionForTest(wrong, fresh),
                "mismatching tag must write POISON");
        assertEquals(0L, canary(fresh));
    }

    @Test
    void b2HandleMixDependsOnVerifyResultAndSessionNonce() {
        byte[] nonceA = randomBytes(32);
        byte[] nonceB = randomBytes(32);
        long base = 0x1122334455667788L;
        long ok = nativeHandleMixForTest(base, 1, nonceA);
        long forged = nativeHandleMixForTest(base, 0, nonceA);
        long otherNonce = nativeHandleMixForTest(base, 1, nonceB);
        assertNotEquals(0L, ok);
        assertNotEquals(ok, forged, "handle bits must depend on raw verify_result");
        assertNotEquals(ok, otherNonce, "handle bits must depend on the session nonce");
        assertEquals(ok, nativeHandleMixForTest(base, 1, nonceA),
                "same inputs must reproduce the same mixed value");
    }

    @Test
    void forcedDigestVerifyResultCannotPromoteHandle() {
        ChimeraRuntime.nativeCreateClientKey();
        ChimeraRuntime.nativeSetAuthContext(randomBytes(32),
                "b7-acct".getBytes(StandardCharsets.UTF_8));
        assertEquals(1, nativeForceVerifyResultForTest(1, 1));
        long handle = ChimeraRuntime.nativeVerifyAuth(
                syntheticResponse(), "b7-hwid".getBytes(StandardCharsets.UTF_8));
        assertNotEquals(0L, handle);
        assertEquals(0L, canary(handle),
                "a forced table VERIFY_ED25519 result must be rejected by the independent path");
    }
    @Test
    void independentBnVerifierMatchesRfc8032Vector() {
        byte[] pub = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        byte[] msg = new byte[0];
        byte[] sig = hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        int stages = nativeEd25519IndependentDebugForTest(pub, msg, sig);
        assertEquals(1000 | 0xFF, stages,
                "BN/SHA-512 verifier must accept RFC8032 test vector 1; stage bits=" + stages);
    }
    @Test
    void decisionProgramClosesPendingWithGenuineSignature() throws Exception {
        KeyPair ed = ed25519KeyPair();
        ChimeraRuntime.nativeSetAuthContext(rawPublicKey(ed.getPublic()),
                "op10-acct".getBytes(StandardCharsets.UTF_8));
        byte[] transcript = "op10-transcript".getBytes(StandardCharsets.UTF_8);
        byte[] signature = sign(ed.getPrivate(), transcript);
        long handle = nativeInstallTestDecisionHandleForTest(randomBytes(32), transcript, signature);
        assertNotEquals(0L, handle);
        assertEquals(0L, canary(handle), "handle starts PENDING");
        byte[] result = ChimeraRuntime.nativeCompute(handle, new byte[]{10, 0});
        assertNotNull(result);
        assertEquals(32, result.length, "op10 returns a fixed 32B zero answer");
        assertArrayEquals(new byte[32], result);
        assertEquals(1L, canary(handle), "PENDING -> VALID after a genuine decision");
        assertEquals(32, ChimeraRuntime.nativeCompute(handle, new byte[]{10, 0}).length);
        assertEquals(1L, canary(handle), "op10 is idempotent on VALID");
    }

    @Test
    void decisionProgramRejectsTamperedSignatureEvenWithForcedTableResult() throws Exception {
        KeyPair ed = ed25519KeyPair();
        ChimeraRuntime.nativeSetAuthContext(rawPublicKey(ed.getPublic()),
                "op10-forge".getBytes(StandardCharsets.UTF_8));
        byte[] transcript = "op10-forged-transcript".getBytes(StandardCharsets.UTF_8);
        byte[] signature = sign(ed.getPrivate(), transcript);
        signature[0] ^= 0x01;
        long handle = nativeInstallTestDecisionHandleForTest(randomBytes(32), transcript, signature);
        assertNotEquals(0L, handle);
        assertEquals(1, nativeForceVerifyResultForTest(1, 1));
        assertEquals(32, ChimeraRuntime.nativeCompute(handle, new byte[]{10, 0}).length);
        assertEquals(0L, canary(handle),
                "independent BN/SHA-512 verification must reject a force-hooked table result");
        assertEquals(32, ChimeraRuntime.nativeCompute(handle, new byte[]{10, 0}).length);
        assertEquals(0L, canary(handle), "POISON is sticky for op10");
    }

    @Test
    void decisionProgramRejectsInvalidHandleAndFlags() throws Exception {
        KeyPair ed = ed25519KeyPair();
        ChimeraRuntime.nativeSetAuthContext(rawPublicKey(ed.getPublic()),
                "op10-shape".getBytes(StandardCharsets.UTF_8));
        byte[] transcript = "op10-shape".getBytes(StandardCharsets.UTF_8);
        long handle = nativeInstallTestDecisionHandleForTest(randomBytes(32), transcript,
                sign(ed.getPrivate(), transcript));
        assertArrayEquals(new byte[0], ChimeraRuntime.nativeCompute(0L, new byte[]{10, 0}),
                "handle 0 may fail closed with an empty array");
        assertEquals(32, ChimeraRuntime.nativeCompute(0x1122334455667788L, new byte[]{10, 0}).length,
                "unknown non-zero handle returns the fixed 32B zero shape");
        assertArrayEquals(new byte[0], ChimeraRuntime.nativeCompute(handle, new byte[]{10, 1}),
                "non-zero flags must fail closed without changing state");
        assertEquals(0L, canary(handle), "invalid flags must not promote the handle");
    }

    @Test
    void forcePendingHookAllowsRepeatedDecisionProgram() throws Exception {
        KeyPair ed = ed25519KeyPair();
        ChimeraRuntime.nativeSetAuthContext(rawPublicKey(ed.getPublic()),
                "op10-repeat".getBytes(StandardCharsets.UTF_8));
        byte[] transcript = "op10-repeat".getBytes(StandardCharsets.UTF_8);
        long handle = nativeInstallTestDecisionHandleForTest(randomBytes(32), transcript,
                sign(ed.getPrivate(), transcript));
        ChimeraRuntime.nativeCompute(handle, new byte[]{10, 0});
        assertEquals(1L, canary(handle));
        assertEquals(1, nativeForcePendingForTest(handle));
        assertEquals(0L, canary(handle));
        ChimeraRuntime.nativeCompute(handle, new byte[]{10, 0});
        assertEquals(1L, canary(handle), "PENDING -> VALID again after force-pending");
    }

    @Test
    void heapWindowMarkerAndCounterAreAvailableForFrida() {
        assertEquals(1, nativeHeapWindowSelfTestForTest(),
                "internal counter must observe marked allocations");
        nativeHeapWindowBeginForTest();
        ChimeraRuntime.nativeCodeSectionIntact();
        assertEquals(0, nativeHeapWindowAllocCountForTest());
        assertEquals(0, nativeHeapWindowEndForTest());
    }
    @Test
    void decryptDataRoundTripsAndWipesScratch() {
        byte[] contentKey = randomBytes(32);
        byte[] resourceKey = randomBytes(32);
        long handle = nativeInstallTestHandleWithResourceKeyForTest(
                contentKey, resourceKey, STATE_VALID);
        assertNotEquals(0L, handle);
        assertEquals(1L, canary(handle));

        byte[] salt = randomBytes(16);
        byte[] nonce = randomBytes(12);
        byte[] aad = "str/7".getBytes(StandardCharsets.UTF_8);
        byte[] plaintext = "chimera-op9-plaintext-marker".getBytes(StandardCharsets.UTF_8);
        byte[] itemKey = itemKey(resourceKey, salt, "str", 7);
        byte[] ciphertext = Crypto.aesGcmEncrypt(itemKey, nonce, plaintext, aad);

        byte[] payload = decryptPayload("str", 7, salt, nonce, aad, ciphertext);
        byte[] decrypted = ChimeraRuntime.nativeCompute(handle, payload);
        assertNotNull(decrypted);
        assertArrayEquals(plaintext, decrypted, "op9 must return the exact plaintext bytes");
        assertEquals(0, nativeArenaResidueForTest(plaintext),
                "decrypt scratch/plaintext buffer must be SecureZeroMemory-wiped");

        ciphertext[0] ^= 0x01;
        byte[] tampered = decryptPayload("str", 7, salt, nonce, aad, ciphertext);
        assertArrayEquals(new byte[0], ChimeraRuntime.nativeCompute(handle, tampered),
                "tampered ciphertext must return empty, never poison bytes");

        long poisonHandle = nativeInstallTestHandleForTest(randomBytes(32), STATE_POISON);
        assertArrayEquals(new byte[0], ChimeraRuntime.nativeCompute(poisonHandle, payload),
                "poison handle must return empty for op9");
    }

    @Test
    void secureWipePrimitiveAndFixedArenaArePresent() {
        assertEquals(1, nativeSecureWipeSelfTestForTest(),
                "SecureZeroMemory must zero the full buffer");
        assertTrue(nativeArenaSizeForTest() >= 64 * 1024, "fixed arena must be preallocated");
    }

    // ------------------------------------------------------------------ helpers

    private static long canary(long handle) {
        byte[] result = ChimeraRuntime.nativeCompute(handle, new byte[]{(byte) 5});
        if (result == null || result.length != 8) return -1L;
        long value = 0;
        for (byte b : result) value = (value << 8) | (b & 0xFFL);
        return value;
    }

    private static byte[] verifyTag(long verifyResult, byte[] nonce, byte[] sessionConst) {
        byte[] prefix = "chimera/verify-tag/v1".getBytes(StandardCharsets.UTF_8);
        ByteBuffer buffer = ByteBuffer.allocate(prefix.length + 8 + 32 + 32);
        buffer.put(prefix);
        buffer.putLong(verifyResult);
        buffer.put(nonce);
        buffer.put(sessionConst);
        return Crypto.sha256(buffer.array());
    }

    private static byte[] itemKey(byte[] resourceKey, byte[] salt, String kind, int id) {
        byte[] kek = Crypto.hkdf(resourceKey,
                "chimera-kek-v1".getBytes(StandardCharsets.UTF_8),
                "kek".getBytes(StandardCharsets.UTF_8), 32);
        return Crypto.hkdf(kek, salt,
                ("chimera/v1/" + kind + "/" + id).getBytes(StandardCharsets.UTF_8), 32);
    }

    private static byte[] decryptPayload(String kind, int id, byte[] salt, byte[] nonce,
                                         byte[] aad, byte[] ciphertext) {
        byte[] kindBytes = kind.getBytes(StandardCharsets.UTF_8);
        ByteBuffer buffer = ByteBuffer.allocate(1 + 1 + kindBytes.length + 4 + 1 + salt.length
                + 12 + 2 + aad.length + 4 + ciphertext.length);
        buffer.put((byte) 9);
        buffer.put((byte) kindBytes.length);
        buffer.put(kindBytes);
        buffer.putInt(id);
        buffer.put((byte) salt.length);
        buffer.put(salt);
        buffer.put(nonce);
        buffer.putShort((short) aad.length);
        buffer.put(aad);
        buffer.putInt(ciphertext.length);
        buffer.put(ciphertext);
        return buffer.array();
    }

    private static byte[] syntheticResponse() {
        SecureRandom random = new SecureRandom();
        Base64.Encoder b64 = Base64.getEncoder();
        byte[] nonce = randomBytes(16);
        byte[] ephemeral = randomBytes(32);
        byte[] wrapped = randomBytes(60);
        byte[] signature = randomBytes(64);
        byte[] token = randomBytes(32);
        long expires = System.currentTimeMillis() / 1000L + 3600L;
        long issued = System.currentTimeMillis() / 1000L;
        String json = "{\"server_nonce\":\"" + b64.encodeToString(nonce)
                + "\",\"server_ephemeral_pub\":\"" + b64.encodeToString(ephemeral)
                + "\",\"wrapped_ck\":\"" + b64.encodeToString(wrapped)
                + "\",\"expires_at\":" + expires
                + ",\"issued_at\":" + issued
                + ",\"sequence\":1"
                + ",\"token\":\"" + b64.encodeToString(token)
                + "\",\"account\":\"b7-acct\""
                + ",\"signature\":\"" + b64.encodeToString(signature) + "\"}";
        return json.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] hex(String value) {
        byte[] out = new byte[value.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
    private static KeyPair ed25519KeyPair() throws Exception {
        return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    private static byte[] rawPublicKey(PublicKey key) {
        byte[] encoded = key.getEncoded();
        return Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
    }

    private static byte[] sign(PrivateKey key, byte[] data) throws Exception {
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(key);
        signer.update(data);
        return signer.sign();
    }
    private static byte[] randomBytes(int size) {
        byte[] bytes = new byte[size];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }
}
