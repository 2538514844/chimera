package dev.chimera.license;

import com.fasterxml.jackson.databind.JsonNode;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * Independent client-side v4 canonical/verification implementation, JDK crypto only. It does not
 * call the server's {@code AuthTranscriptV4}, so a server canonical bug cannot hide a broken wire
 * contract.
 */
final class TestClientCryptoV4 {

    static final String ACTIVATE_RESPONSE_DOMAIN = "chimera-auth-v4/activate-response";
    static final String HEARTBEAT_RESPONSE_DOMAIN = "chimera-auth-v4/heartbeat-response";

    private static final byte[] ED25519_SPKI_PREFIX = {
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
    };
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private TestClientCryptoV4() {
    }

    static byte[] encode(String domain, String... fields) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(256);
        write(out, domain);
        for (String field : fields) {
            write(out, field == null ? "" : field);
        }
        return out.toByteArray();
    }

    private static void write(ByteArrayOutputStream out, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        out.write((bytes.length >>> 24) & 0xff);
        out.write((bytes.length >>> 16) & 0xff);
        out.write((bytes.length >>> 8) & 0xff);
        out.write(bytes.length & 0xff);
        out.write(bytes, 0, bytes.length);
    }

    static byte[] canonicalActivate(JsonNode node) {
        return encode(ACTIVATE_RESPONSE_DOMAIN,
                node.get("v").asText(),
                node.get("account").asText(),
                node.get("hwid").asText(),
                node.get("client_ephemeral_pub").asText(),
                node.get("client_nonce").asText(),
                node.get("server_ephemeral_pub").asText(),
                node.get("server_nonce").asText(),
                node.get("token").asText(),
                node.get("sequence").asText(),
                node.get("issued_at").asText(),
                node.get("expires_at").asText(),
                node.get("server_time").asText(),
                node.hasNonNull("resource_ck") ? node.get("resource_ck").asText() : "",
                node.hasNonNull("license_id") ? node.get("license_id").asText() : "",
                node.hasNonNull("client_ip") ? node.get("client_ip").asText() : "");
    }

    static byte[] canonicalHeartbeat(JsonNode node, String presentedToken) {
        return encode(HEARTBEAT_RESPONSE_DOMAIN,
                node.get("v").asText(),
                node.get("hwid").asText(),
                node.get("client_nonce").asText(),
                tokenHashHex(presentedToken),
                node.get("token").asText(),
                node.get("sequence").asText(),
                node.get("server_nonce").asText(),
                node.get("issued_at").asText(),
                node.get("expires_at").asText(),
                node.get("server_time").asText(),
                node.hasNonNull("resource_ck") ? node.get("resource_ck").asText() : "",
                node.hasNonNull("server_ephemeral_pub")
                        ? node.get("server_ephemeral_pub").asText() : "",
                node.hasNonNull("license_id") ? node.get("license_id").asText() : "",
                node.hasNonNull("client_ip") ? node.get("client_ip").asText() : "");
    }

    static boolean verifyActivate(JsonNode node, PublicKey key) throws Exception {
        return verify(key, canonicalActivate(node), node.get("signature").asText());
    }

    static boolean verifyHeartbeat(JsonNode node, String presentedToken, PublicKey key)
            throws Exception {
        return verify(key, canonicalHeartbeat(node, presentedToken), node.get("signature").asText());
    }

    static boolean verify(PublicKey key, byte[] message, String signatureBase64) throws Exception {
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(key);
        verifier.update(message);
        try {
            return verifier.verify(Base64.getDecoder().decode(signatureBase64));
        } catch (IllegalArgumentException | java.security.SignatureException e) {
            return false;
        }
    }

    static PublicKey ed25519PublicKey(byte[] raw32) throws Exception {
        byte[] encoded = new byte[ED25519_SPKI_PREFIX.length + raw32.length];
        System.arraycopy(ED25519_SPKI_PREFIX, 0, encoded, 0, ED25519_SPKI_PREFIX.length);
        System.arraycopy(raw32, 0, encoded, ED25519_SPKI_PREFIX.length, raw32.length);
        return KeyFactory.getInstance("Ed25519")
                .generatePublic(new X509EncodedKeySpec(encoded));
    }

    /**
     * Unwraps the v4 {@code resource_ck} envelope with the activation-time client key:
     * {@code shared = X25519(client_priv, server_ephemeral_pub)},
     * {@code wrapKey = HKDF-SHA256(shared, salt=UTF8(client_nonce), info="chimera/v1/v4/ck", L=32)},
     * AES-256-GCM with a 12-byte nonce prefix and AAD {@code "chimera/v1/v4/ck|account|hwid"}.
     * Throws {@code AEADBadTagException} when the envelope is bound to another key or HWID.
     */
    static byte[] unpackResourceKey(PrivateKey clientPrivate, String clientNonceB64,
                                    String serverEphemeralB64, String resourceCkB64,
                                    String account, String hwid) throws Exception {
        byte[] envelope = Base64.getDecoder().decode(resourceCkB64);
        byte[] gcmNonce = Arrays.copyOfRange(envelope, 0, 12);
        byte[] ciphertext = Arrays.copyOfRange(envelope, 12, envelope.length);
        byte[] shared = TestClientCrypto.x25519SharedSecret(clientPrivate,
                Base64.getDecoder().decode(serverEphemeralB64));
        byte[] wrapKey = TestClientCrypto.hkdf(shared,
                clientNonceB64.getBytes(StandardCharsets.UTF_8),
                "chimera/v1/v4/ck".getBytes(StandardCharsets.UTF_8), 32);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(wrapKey, "AES"),
                new GCMParameterSpec(128, gcmNonce));
        cipher.updateAAD(("chimera/v1/v4/ck|" + account + "|" + hwid)
                .getBytes(StandardCharsets.UTF_8));
        return cipher.doFinal(ciphertext);
    }

    static String tokenHashHex(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            char[] out = new char[hash.length * 2];
            for (int i = 0; i < hash.length; i++) {
                int value = hash[i] & 0xff;
                out[i * 2] = HEX[value >>> 4];
                out[i * 2 + 1] = HEX[value & 0xf];
            }
            return new String(out);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
