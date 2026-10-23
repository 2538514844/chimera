package dev.chimera.license;

import com.fasterxml.jackson.databind.JsonNode;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Independent client-side implementation of the v3 wire protocol, built only from JDK crypto.
 * It deliberately does not call {@code dev.chimera.license.crypto.CryptoUtils} for the checks it
 * performs, so a server-side bug cannot hide a broken wire contract.
 *
 * <p>B-Full lite + KI-28 key contract implemented here:
 * {@code user_key = HKDF-SHA256(master_key, salt=UTF8("chimera/uck/v1"),
 * info=BE64(account_id)||UTF8(hwid), L=32)} and
 * {@code poisoned[i] = user_key[(i + 1) % 32]}. The long-lived ResourceKey is delivered inside
 * {@code resource_ck} encrypted with
 * {@code HKDF-SHA256(user_key, zeros32, "chimera/resource-wrap/v1")} (AES-256-GCM,
 * AAD {@code "chimera-resource/v1|account|hwid"}).</p>
 */
final class TestClientCrypto {

    static final String MASTER_KEY_HEX =
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    /** Fixed ResourceKey used by tests; the server is started with the same hex via properties. */
    static final String RESOURCE_KEY_HEX =
            "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    private static final byte[] RESOURCE_WRAP_INFO =
            "chimera/resource-wrap/v1".getBytes(StandardCharsets.UTF_8);

    private static final byte[] X25519_SPKI_PREFIX =
            hex("302a300506032b656e032100");
    private static final byte[] ED25519_SPKI_PREFIX =
            hex("302a300506032b6570032100");

    private TestClientCrypto() {
    }

    static byte[] masterKey() {
        return hex(MASTER_KEY_HEX);
    }

    static byte[] hex(String value) {
        return HexFormat.of().parseHex(value);
    }

    static String b64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    static byte[] unb64(String value) {
        return Base64.getDecoder().decode(value);
    }

    static byte[] concat(byte[] first, byte[] second) {
        byte[] out = new byte[first.length + second.length];
        System.arraycopy(first, 0, out, 0, first.length);
        System.arraycopy(second, 0, out, first.length, second.length);
        return out;
    }

    // ---------------------------------------------------------------- B-Full lite key contract

    static byte[] deriveUserContentKey(byte[] masterKey, long accountId, String hwid) {
        byte[] hwidBytes = hwid.getBytes(StandardCharsets.UTF_8);
        byte[] info = new byte[8 + hwidBytes.length];
        ByteBuffer.wrap(info).putLong(accountId);
        System.arraycopy(hwidBytes, 0, info, 8, hwidBytes.length);
        return hkdf(masterKey, "chimera/uck/v1".getBytes(StandardCharsets.UTF_8), info, 32);
    }

    static byte[] resourceKey() {
        return hex(RESOURCE_KEY_HEX);
    }

    static byte[] poisonUserContentKey(byte[] userContentKey) {
        return rotateLeft(userContentKey);
    }

    static byte[] poisonResourceKey(byte[] resourceKey) {
        return rotateLeft(resourceKey);
    }

    private static byte[] rotateLeft(byte[] key) {
        byte[] poisoned = new byte[key.length];
        for (int i = 0; i < poisoned.length; i++) {
            poisoned[i] = key[(i + 1) % key.length];
        }
        return poisoned;
    }

    /** Envelope key contract: HKDF-SHA256(ikm=UserContentKey, salt=zeros32, info, L=32). */
    static byte[] resourceWrapKey(byte[] userContentKey) {
        return hkdf(userContentKey, null, RESOURCE_WRAP_INFO, 32);
    }

    static byte[] unpackResourceKey(byte[] userContentKey, String resourceCkB64,
                                    String account, String hwid) throws Exception {
        byte[] envelope = unb64(resourceCkB64);
        byte[] gcmNonce = Arrays.copyOfRange(envelope, 0, 12);
        byte[] ciphertext = Arrays.copyOfRange(envelope, 12, envelope.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec(resourceWrapKey(userContentKey), "AES"),
                new GCMParameterSpec(128, gcmNonce));
        cipher.updateAAD(("chimera-resource/v1|" + account + "|" + hwid)
                .getBytes(StandardCharsets.UTF_8));
        return cipher.doFinal(ciphertext);
    }

    // ---------------------------------------------------------------- HKDF / AES-GCM

    static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int length) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(salt == null || salt.length == 0 ? new byte[32] : salt, "HmacSHA256"));
            byte[] prk = mac.doFinal(ikm);
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            byte[] out = new byte[length];
            byte[] previous = new byte[0];
            int offset = 0;
            int counter = 1;
            while (offset < length) {
                mac.update(previous);
                mac.update(info);
                mac.update((byte) counter);
                previous = mac.doFinal();
                int chunk = Math.min(previous.length, length - offset);
                System.arraycopy(previous, 0, out, offset, chunk);
                offset += chunk;
                counter++;
            }
            Arrays.fill(prk, (byte) 0);
            return out;
        } catch (Exception e) {
            throw new IllegalStateException("client HKDF failed", e);
        }
    }

    static byte[] sealContent(byte[] key, byte[] plaintext) throws Exception {
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD("test-content".getBytes(StandardCharsets.UTF_8));
        byte[] ciphertext = cipher.doFinal(plaintext);
        return concat(nonce, ciphertext);
    }

    static byte[] openContent(byte[] key, byte[] sealed) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, Arrays.copyOfRange(sealed, 0, 12)));
        cipher.updateAAD("test-content".getBytes(StandardCharsets.UTF_8));
        return cipher.doFinal(Arrays.copyOfRange(sealed, 12, sealed.length));
    }

    // ---------------------------------------------------------------- X25519 / Ed25519

    static PublicKey x25519PublicKey(byte[] raw32) throws Exception {
        return KeyFactory.getInstance("X25519")
                .generatePublic(new X509EncodedKeySpec(concat(X25519_SPKI_PREFIX, raw32)));
    }

    static PublicKey ed25519PublicKey(byte[] raw32) throws Exception {
        return KeyFactory.getInstance("Ed25519")
                .generatePublic(new X509EncodedKeySpec(concat(ED25519_SPKI_PREFIX, raw32)));
    }

    static byte[] x25519SharedSecret(PrivateKey privateKey, byte[] peerRaw) throws Exception {
        KeyAgreement agreement = KeyAgreement.getInstance("X25519");
        agreement.init(privateKey);
        agreement.doPhase(x25519PublicKey(peerRaw), true);
        return agreement.generateSecret();
    }

    // ---------------------------------------------------------------- wrapped_ck unpack

    static byte[] unpackContentKey(PrivateKey clientPrivate,
                                   String serverEphemeralB64,
                                   String serverNonceB64,
                                   String wrappedB64,
                                   String account,
                                   String hwid) throws Exception {
        byte[] wrapped = unb64(wrappedB64);
        byte[] gcmNonce = Arrays.copyOfRange(wrapped, 0, 12);
        byte[] ciphertext = Arrays.copyOfRange(wrapped, 12, wrapped.length);
        byte[] shared = x25519SharedSecret(clientPrivate, unb64(serverEphemeralB64));
        byte[] wrapKey = hkdf(shared, unb64(serverNonceB64),
                "chimera/wrap/v1".getBytes(StandardCharsets.UTF_8), 32);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(wrapKey, "AES"),
                new GCMParameterSpec(128, gcmNonce));
        cipher.updateAAD(("chimera-wrap/v1|" + account + "|" + hwid).getBytes(StandardCharsets.UTF_8));
        return cipher.doFinal(ciphertext);
    }

    // ---------------------------------------------------------------- v3 canonical verification

    static boolean verifyActivate(JsonNode node, PublicKey ed25519PublicKey) throws Exception {
        String canonical = "{\"expires_at\":" + node.get("expires_at").asLong()
                + ",\"issued_at\":" + node.get("issued_at").asLong()
                + ",\"resource_ck\":\"" + node.get("resource_ck").asText()
                + "\",\"sequence\":" + node.get("sequence").asLong()
                + ",\"server_ephemeral_pub\":\"" + node.get("server_ephemeral_pub").asText()
                + "\",\"server_nonce\":\"" + node.get("server_nonce").asText()
                + "\",\"token\":\"" + node.get("token").asText()
                + "\",\"wrapped_ck\":\"" + node.get("wrapped_ck").asText() + "\"}";
        return verify(ed25519PublicKey, canonical, node.get("signature").asText());
    }

    static boolean verifyHeartbeat(JsonNode node, String token, PublicKey ed25519PublicKey) throws Exception {
        String canonical = "{\"expires_at\":" + node.get("expires_at").asLong()
                + ",\"issued_at\":" + node.get("issued_at").asLong()
                + ",\"sequence\":" + node.get("sequence").asLong()
                + ",\"server_nonce\":\"" + node.get("server_nonce").asText()
                + "\",\"token\":\"" + token + "\"}";
        return verify(ed25519PublicKey, canonical, node.get("signature").asText());
    }

    private static boolean verify(PublicKey publicKey, String canonical, String signatureB64) throws Exception {
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(publicKey);
        verifier.update(canonical.getBytes(StandardCharsets.UTF_8));
        return verifier.verify(unb64(signatureB64));
    }
}
