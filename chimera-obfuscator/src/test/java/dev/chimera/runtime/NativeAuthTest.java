package dev.chimera.runtime;

import dev.chimera.auth.NativeAuthLibrary;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * M8: proves that Ed25519 verification + X25519 unwrap happen in native code and that a fake
 * signature yields a formatted poison key (never null, never an exception).
 */
class NativeAuthTest {

    private static final String ACCOUNT = "player@example.com";
    private static final String HWID = "hwid-native-test";

    private static final byte[] ED25519_SPKI = {
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
    };
    private static final byte[] X25519_SPKI = {
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00
    };

    @BeforeAll
    static void loadNative() {
        NativeAuthLibrary.prepareIsolatedCopy();
        assertTrue(ChimeraRuntime.nativeAuthAvailable(), "native auth library must load");
    }

    private record ServerLicense(String json, byte[] contentKey) {
    }

    private static ServerLicense buildResponse(KeyPair ed25519, KeyPair serverX25519,
                                               byte[] contentKey, String hwid, boolean tamperSig)
            throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] clientPub = ChimeraRuntime.nativeCreateClientKey();
        assertNotNull(clientPub);
        assertEquals(32, clientPub.length);
        ChimeraRuntime.nativeSetAuthContext(rawEd(ed25519.getPublic()), ACCOUNT.getBytes(StandardCharsets.UTF_8));

        byte[] shared = x25519(serverX25519.getPrivate(), clientPub);
        byte[] nonce = new byte[16];
        random.nextBytes(nonce);
        byte[] wrapKey = hkdf(shared, nonce, "chimera/wrap/v1".getBytes(StandardCharsets.UTF_8), 32);
        byte[] aesNonce = new byte[12];
        random.nextBytes(aesNonce);
        byte[] aad = ("chimera-wrap/v1|" + ACCOUNT + "|" + hwid).getBytes(StandardCharsets.UTF_8);
        byte[] wrappedPayload = gcm(Cipher.ENCRYPT_MODE, wrapKey, aesNonce, contentKey, aad);
        byte[] wrapped = new byte[12 + wrappedPayload.length];
        System.arraycopy(aesNonce, 0, wrapped, 0, 12);
        System.arraycopy(wrappedPayload, 0, wrapped, 12, wrappedPayload.length);

        String nonceB64 = b64(nonce);
        String ephemeralB64 = b64(rawX25519(serverX25519.getPublic()));
        String wrappedB64 = b64(wrapped);
        String token = b64(randomBytes(random, 32));
        long expires = (System.currentTimeMillis() / 1000L) + 3600L;
        long issued = System.currentTimeMillis() / 1000L;
        long sequence = 1L;
        String canonical = "{\"expires_at\":" + expires
                + ",\"issued_at\":" + issued
                + ",\"sequence\":" + sequence
                + ",\"server_ephemeral_pub\":\"" + ephemeralB64
                + "\",\"server_nonce\":\"" + nonceB64
                + "\",\"token\":\"" + token
                + "\",\"wrapped_ck\":\"" + wrappedB64 + "\"}";
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(ed25519.getPrivate());
        signer.update(canonical.getBytes(StandardCharsets.UTF_8));
        byte[] signature = signer.sign();
        if (tamperSig) signature[0] ^= 0x01;

        String json = "{\"server_nonce\":\"" + nonceB64
                + "\",\"server_ephemeral_pub\":\"" + ephemeralB64
                + "\",\"wrapped_ck\":\"" + wrappedB64
                + "\",\"expires_at\":" + expires
                + ",\"sequence\":" + sequence
                + ",\"issued_at\":" + issued
                + ",\"token\":\"" + token
                + "\",\"account\":\"" + ACCOUNT
                + "\",\"signature\":\"" + b64(signature) + "\"}";
        return new ServerLicense(json, contentKey);
    }

    @Test
    void validResponseReturnsUsableSessionHandleAndCanary() throws Exception {
        KeyPair ed = ed25519();
        KeyPair serverX = x25519Pair();
        byte[] contentKey = randomBytes(new SecureRandom(), 32);
        ServerLicense license = buildResponse(ed, serverX, contentKey, HWID, false);
        long handle = ChimeraRuntime.nativeVerifyAuth(
                license.json().getBytes(StandardCharsets.UTF_8), HWID.getBytes(StandardCharsets.UTF_8));
        assertNotEquals(0L, handle, "a handle must be returned (never key bytes)");
        assertEquals(1L, canary(handle), "valid handle must pass the native canary");
        assertTrue(ChimeraRuntime.nativeCheckHandle(handle) != 0L);
    }

    @Test
    void fakeSignatureReturnsHandleWhoseCanaryFailsNotAnException() throws Exception {
        KeyPair ed = ed25519();
        KeyPair serverX = x25519Pair();
        byte[] contentKey = randomBytes(new SecureRandom(), 32);
        ServerLicense license = buildResponse(ed, serverX, contentKey, HWID, true);
        long handle = ChimeraRuntime.nativeVerifyAuth(
                license.json().getBytes(StandardCharsets.UTF_8), HWID.getBytes(StandardCharsets.UTF_8));
        assertNotEquals(0L, handle, "failure must still return a long-shaped handle");
        assertEquals(0L, canary(handle), "tampered signature must not pass the canary");
    }

    @Test
    void wrongHwidFailsAadAndCanary() throws Exception {
        KeyPair ed = ed25519();
        KeyPair serverX = x25519Pair();
        byte[] contentKey = randomBytes(new SecureRandom(), 32);
        ServerLicense license = buildResponse(ed, serverX, contentKey, HWID, false);
        long handle = ChimeraRuntime.nativeVerifyAuth(
                license.json().getBytes(StandardCharsets.UTF_8), "other-hwid".getBytes(StandardCharsets.UTF_8));
        assertNotEquals(0L, handle);
        assertEquals(0L, canary(handle));
    }

    @Test
    void invalidHandleComputeReturnsPoisonWithoutCrash() throws Exception {
        long bogus = 0x1234_5678_9abc_def0L;
        assertEquals(0L, canary(bogus), "invalid handle canary must be 0, not a valid session");
        byte[] item = ChimeraRuntime.nativeCompute(bogus, new byte[]{
                1, 3, 'v', 'm', 'x', 0, 0, 0, 7, 16, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
        assertNotNull(item);
        assertEquals(32, item.length, "invalid handle derive must still return 32 poison bytes");
    }

    @Test
    void antiDebugPolicyIsConfigurableAndDoesNotPoisonNormalSessions() throws Exception {
        // Default policy (telemetry) and strict mode must both keep the real key when no
        // debugger/Frida signal is present; the strict decision only applies to detected signals.
        for (int mode : new int[]{0, 1}) {
            ChimeraRuntime.nativeSetAntiDebugMode(mode);
            KeyPair ed = ed25519();
            KeyPair serverX = x25519Pair();
            byte[] contentKey = randomBytes(new SecureRandom(), 32);
            ServerLicense license = buildResponse(ed, serverX, contentKey, HWID, false);
            long handle = ChimeraRuntime.nativeVerifyAuth(
                    license.json().getBytes(StandardCharsets.UTF_8),
                    HWID.getBytes(StandardCharsets.UTF_8));
            assertEquals(1L, canary(handle),
                    "mode " + mode + " must not poison a clean session");
            assertTrue(ChimeraRuntime.nativeAntiDebugSignalCount() >= 0);
        }
        ChimeraRuntime.nativeSetAntiDebugMode(2);
        ChimeraRuntime.nativeSetAntiDebugMode(0);
    }

    @Test
    void nativeItemKeyMatchesJavaKdf() throws Exception {
        KeyPair ed = ed25519();
        KeyPair serverX = x25519Pair();
        byte[] contentKey = randomBytes(new SecureRandom(), 32);
        ServerLicense license = buildResponse(ed, serverX, contentKey, HWID, false);
        long handle = ChimeraRuntime.nativeVerifyAuth(
                license.json().getBytes(StandardCharsets.UTF_8), HWID.getBytes(StandardCharsets.UTF_8));
        byte[] salt = new byte[16];
        byte[] kind = "str".getBytes(StandardCharsets.UTF_8);
        java.nio.ByteBuffer params = java.nio.ByteBuffer.allocate(1 + 1 + kind.length + 4 + 1 + salt.length);
        params.put((byte) 1);
        params.put((byte) kind.length);
        params.put(kind);
        params.putInt(31);
        params.put((byte) salt.length);
        params.put(salt);
        byte[] nativeKey = ChimeraRuntime.nativeCompute(handle, params.array());
        byte[] kek = hkdf(contentKey, "chimera-kek-v1".getBytes(StandardCharsets.UTF_8),
                "kek".getBytes(StandardCharsets.UTF_8), 32);
        byte[] expected = hkdf(kek, salt,
                "chimera/v1/str/31".getBytes(StandardCharsets.UTF_8), 32);
        assertNotNull(nativeKey);
        assertEquals(32, nativeKey.length);
        assertArrayEquals(expected, nativeKey,
                "native item key must equal Java HKDF derivation");
    }

    @Test
    void nativeHmacOpMatchesJavaHmac() throws Exception {
        KeyPair ed = ed25519();
        KeyPair serverX = x25519Pair();
        byte[] contentKey = randomBytes(new SecureRandom(), 32);
        ServerLicense license = buildResponse(ed, serverX, contentKey, HWID, false);
        long handle = ChimeraRuntime.nativeVerifyAuth(
                license.json().getBytes(StandardCharsets.UTF_8), HWID.getBytes(StandardCharsets.UTF_8));
        byte[] data = "manifest-bytes".getBytes(StandardCharsets.UTF_8);
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        java.io.DataOutputStream out = new java.io.DataOutputStream(bos);
        out.writeByte(2);
        out.writeInt(data.length);
        out.write(data);
        out.flush();
        byte[] nativeMac = ChimeraRuntime.nativeCompute(handle, bos.toByteArray());
        assertNotNull(nativeMac, "native HMAC must return bytes");
        assertEquals(32, nativeMac.length, "native HMAC must return 32 bytes");
        byte[] kek = hkdf(contentKey, "chimera-kek-v1".getBytes(StandardCharsets.UTF_8),
                "kek".getBytes(StandardCharsets.UTF_8), 32);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(kek, "HmacSHA256"));
        assertArrayEquals(mac.doFinal(data), nativeMac,
                "native HMAC op must equal Java HMAC(kek, data)");
    }

    // ------------------------------------------------------------------ B7-pre/KI-26 lifecycle

    @Test
    void reconnectStormKeepsEveryValidHandleAlive() throws Exception {
        long[] handles = new long[20];
        for (int i = 0; i < handles.length; i++) {
            handles[i] = verifyHandle();
        }
        for (int i = 0; i < handles.length; i++) {
            assertEquals(1L, canary(handles[i]),
                    "handle " + i + " must not be evicted by a 20-reconnect storm");
        }
        assertEquals(1L, canary(handles[19]), "the newest session must stay usable");
    }

    @Test
    void fullTableEvictsLeastRecentlyUsedHandleNotActiveSession() throws Exception {
        long[] handles = new long[65];
        for (int i = 0; i < 64; i++) {
            handles[i] = verifyHandle();
        }
        // Keep handles[1] active: it must survive the LRU eviction triggered by handle 64.
        assertTrue(ChimeraRuntime.nativeCheckHandle(handles[1]) != 0L);
        handles[64] = verifyHandle();
        assertEquals(1L, canary(handles[64]), "newest handle must be valid");
        assertEquals(1L, canary(handles[1]), "recently used handle must survive LRU eviction");
        assertEquals(0L, canary(handles[0]), "least recently used handle must be evicted");
    }

    @Test
    void handleTtlIsClampedToTheSpecifiedWindow() {
        long original = ChimeraRuntime.nativeHandleTtlMs();
        long expectedFloor = ChimeraRuntime.isDevNativeBuild() ? 1_000L : 300_000L;
        try {
            assertEquals(expectedFloor, ChimeraRuntime.nativeSetHandleTtlMs(1_000L),
                    "TTL below the build's floor must clamp");
            assertEquals(900_000L, ChimeraRuntime.nativeSetHandleTtlMs(3_600_000L),
                    "TTL above 15 minutes must clamp to the ceiling");
            assertEquals(600_000L, ChimeraRuntime.nativeSetHandleTtlMs(600_000L),
                    "a value inside the window is kept");
        } finally {
            ChimeraRuntime.nativeSetHandleTtlMs(original);
        }
    }

    @Test
    void expiredHandleIsInvalidatedByRealTtlWait() throws Exception {
        Assumptions.assumeTrue(ChimeraRuntime.isDevNativeBuild(),
                "real-wait TTL test requires the dev DLL with a 1 s floor");
        long original = ChimeraRuntime.nativeHandleTtlMs();
        try {
            assertEquals(1_000L, ChimeraRuntime.nativeSetHandleTtlMs(1_000L));
            long handle = verifyHandle();
            assertEquals(1L, canary(handle));
            Thread.sleep(1_500L);
            assertEquals(0L, canary(handle),
                    "a real wall-clock wait past the TTL must invalidate the handle (no QA backdating)");
        } finally {
            ChimeraRuntime.nativeSetHandleTtlMs(original);
        }
    }

    @Test
    void expiredHandleIsInvalidatedWithoutWaitingForTheTtl() throws Exception {
        long handle = verifyHandle();
        assertEquals(1L, canary(handle));
        assertEquals(1, ChimeraRuntime.nativeExpireHandleForTest(handle),
                "QA hook must find the live handle");
        assertEquals(0L, canary(handle), "expired handle must fail the canary");
        assertEquals(0, ChimeraRuntime.nativeExpireHandleForTest(handle),
                "expired handle is already gone from the table");
    }

    @Test
    void revokedHandleCannotBeUsedForDerivation() throws Exception {
        long handle = verifyHandle();
        assertEquals(1L, canary(handle));
        assertEquals(1, ChimeraRuntime.nativeRevokeHandle(handle), "revoke must find the handle");
        assertEquals(0L, canary(handle), "revoked handle must fail the canary");
        assertEquals(0, ChimeraRuntime.nativeRevokeHandle(handle), "revoke is idempotent");
        byte[] item = ChimeraRuntime.nativeCompute(handle, new byte[]{
                1, 3, 'v', 'm', 'x', 0, 0, 0, 7, 16, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
        assertNotNull(item);
        assertEquals(32, item.length, "revoked handle derive must return poison bytes, not leak");
    }

    private static long verifyHandle() throws Exception {
        KeyPair ed = ed25519();
        KeyPair serverX = x25519Pair();
        byte[] contentKey = randomBytes(new SecureRandom(), 32);
        ServerLicense license = buildResponse(ed, serverX, contentKey, HWID, false);
        long handle = ChimeraRuntime.nativeVerifyAuth(
                license.json().getBytes(StandardCharsets.UTF_8), HWID.getBytes(StandardCharsets.UTF_8));
        assertNotEquals(0L, handle, "every verification path must return a long-shaped handle");
        return handle;
    }

    @Test
    void javaLayerNoLongerPerformsAsymmetricCrypto() {
        assertThrows(NoSuchMethodException.class, () -> ChimeraRuntime.class.getDeclaredMethod(
                "verifyEd25519", byte[].class, byte[].class, byte[].class));
        assertThrows(NoSuchMethodException.class, () -> ChimeraRuntime.class.getDeclaredMethod(
                "x25519", KeyPair.class, byte[].class));
    }

    private static long canary(long handle) {
        byte[] value = ChimeraRuntime.nativeCompute(handle, new byte[]{5});
        assertNotNull(value);
        assertEquals(8, value.length);
        return java.nio.ByteBuffer.wrap(value).getLong();
    }

    private static KeyPair ed25519() throws Exception {
        return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    private static KeyPair x25519Pair() throws Exception {
        return KeyPairGenerator.getInstance("X25519").generateKeyPair();
    }

    private static byte[] rawEd(java.security.PublicKey key) {
        byte[] encoded = key.getEncoded();
        byte[] raw = new byte[32];
        System.arraycopy(encoded, encoded.length - 32, raw, 0, 32);
        return raw;
    }

    private static byte[] rawX25519(java.security.PublicKey key) {
        byte[] encoded = key.getEncoded();
        byte[] raw = new byte[32];
        System.arraycopy(encoded, encoded.length - 32, raw, 0, 32);
        return raw;
    }

    private static byte[] x25519(java.security.PrivateKey priv, byte[] peerRaw) throws Exception {
        java.security.PublicKey peer = KeyFactory.getInstance("X25519")
                .generatePublic(new X509EncodedKeySpec(concat(X25519_SPKI, peerRaw)));
        KeyAgreement agreement = KeyAgreement.getInstance("X25519");
        agreement.init(priv);
        agreement.doPhase(peer, true);
        return agreement.generateSecret();
    }

    private static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int len) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] prk = mac.doFinal(ikm);
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        byte[] out = new byte[len];
        byte[] previous = new byte[0];
        int offset = 0;
        int counter = 1;
        while (offset < len) {
            mac.update(previous);
            mac.update(info);
            mac.update((byte) counter);
            previous = mac.doFinal();
            int take = Math.min(previous.length, len - offset);
            System.arraycopy(previous, 0, out, offset, take);
            offset += take;
            counter++;
        }
        return out;
    }

    private static byte[] gcm(int mode, byte[] key, byte[] nonce, byte[] input, byte[] aad) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(input);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static byte[] randomBytes(SecureRandom random, int len) {
        byte[] out = new byte[len];
        random.nextBytes(out);
        return out;
    }

    private static String b64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }
}
