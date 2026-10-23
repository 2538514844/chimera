package dev.chimera.runtime;

import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
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
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** F: v4 client cryptography (canonical signature + ECDH resource-key envelope). */
class ChimeraV4SessionTest {

    @Test
    void hkdfMatchesRfc5869Case1() throws Exception {
        byte[] ikm = new byte[22];
        java.util.Arrays.fill(ikm, (byte) 0x0b);
        byte[] salt = java.util.HexFormat.of().parseHex("000102030405060708090a0b0c");
        byte[] info = java.util.HexFormat.of().parseHex("f0f1f2f3f4f5f6f7f8f9");
        byte[] okm = ChimeraV4Session.hkdf(ikm, salt, info, 42);
        String expected = "3cb25f25faacd57a90434f64d0362f2a"
                + "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                + "34007208d5b887185865";
        assertArrayEquals(java.util.HexFormat.of().parseHex(expected), okm);
    }

    @Test
    void unwrapsServerEnvelope() throws Exception {
        KeyPair client = KeyPairGenerator.getInstance("X25519").generateKeyPair();
        KeyPair server = KeyPairGenerator.getInstance("X25519").generateKeyPair();
        byte[] clientPubRaw = rawPublic(client.getPublic());
        byte[] serverPubRaw = rawPublic(server.getPublic());
        String clientNonce = "00112233445566778899aabbccddeeff";
        String account = "tester";
        String hwid = "hw-123";

        // Server side: shared = X25519(serverPriv, clientPub), wrap with HKDF+AES-GCM.
        KeyAgreement agreement = KeyAgreement.getInstance("X25519");
        agreement.init(server.getPrivate());
        agreement.doPhase(KeyFactory.getInstance("X25519").generatePublic(
                x25519Spec(clientPubRaw)), true);
        byte[] shared = agreement.generateSecret();
        byte[] wrapKey = ChimeraV4Session.hkdf(shared,
                clientNonce.getBytes(StandardCharsets.UTF_8),
                "chimera/v1/v4/ck".getBytes(StandardCharsets.UTF_8), 32);
        byte[] resourceKey = new byte[32];
        new SecureRandom().nextBytes(resourceKey);
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        byte[] aad = ("chimera/v1/v4/ck|" + account + "|" + hwid)
                .getBytes(StandardCharsets.UTF_8);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(wrapKey, "AES"),
                new GCMParameterSpec(128, nonce));
        cipher.updateAAD(aad);
        byte[] sealed = cipher.doFinal(resourceKey);
        byte[] envelope = new byte[nonce.length + sealed.length];
        System.arraycopy(nonce, 0, envelope, 0, nonce.length);
        System.arraycopy(sealed, 0, envelope, nonce.length, sealed.length);

        byte[] recovered = ChimeraV4Session.unwrapResourceKey(client.getPrivate(), serverPubRaw,
                clientNonce, account, hwid, envelope);
        assertArrayEquals(resourceKey, recovered);

        // A different HWID must fail closed (AAD mismatch).
        byte[] tampered = ChimeraV4Session.unwrapResourceKey(client.getPrivate(), serverPubRaw,
                clientNonce, account, "other-hwid", envelope);
        assertTrue(tampered == null, "AAD mismatch must fail closed");
    }

    @Test
    void verifiesCanonicalResponseSignature() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
        KeyPair serverKeys = generator.generateKeyPair();
        byte[] serverRaw = rawPublic(serverKeys.getPublic());

        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("v", "4");
        fields.put("account", "tester");
        fields.put("hwid", "hw-123");
        fields.put("client_ephemeral_pub", "Y2xpZW50");
        fields.put("client_nonce", "n0nce");
        fields.put("server_ephemeral_pub", "c2VydmVy");
        fields.put("server_nonce", "s3rv3r");
        fields.put("token", "token-value");
        fields.put("sequence", "1");
        fields.put("issued_at", "1000");
        fields.put("expires_at", "2000");
        fields.put("server_time", "1000");
        fields.put("resource_ck", "ZW52");

        byte[] canonical = canonical(fields);
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(serverKeys.getPrivate());
        signer.update(canonical);
        fields.put("signature", java.util.Base64.getEncoder().encodeToString(signer.sign()));

        assertTrue(ChimeraV4Session.verifyActivateSignature(serverRaw, fields));

        fields.put("account", "attacker");
        assertFalse(ChimeraV4Session.verifyActivateSignature(serverRaw, fields),
                "tampered field must fail");
    }

    private static byte[] canonical(Map<String, String> fields) throws Exception {
        String[] order = {"account", "hwid", "client_ephemeral_pub", "client_nonce",
                "server_ephemeral_pub", "server_nonce", "token", "sequence", "issued_at",
                "expires_at", "server_time", "resource_ck"};
        java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();
        java.io.DataOutputStream out = new java.io.DataOutputStream(buffer);
        transcript(out, "chimera-auth-v4/activate-response");
        transcript(out, "4");
        for (String field : order) {
            transcript(out, fields.getOrDefault(field, ""));
        }
        return buffer.toByteArray();
    }

    private static void transcript(java.io.DataOutputStream out, String value) throws Exception {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        out.writeInt(bytes.length);
        out.write(bytes);
    }

    private static byte[] rawPublic(java.security.PublicKey key) {
        byte[] encoded = key.getEncoded();
        return java.util.Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
    }

    private static java.security.spec.X509EncodedKeySpec x25519Spec(byte[] raw) {
        byte[] prefix = java.util.HexFormat.of().parseHex("302a300506032b656e032100");
        byte[] encoded = new byte[prefix.length + raw.length];
        System.arraycopy(prefix, 0, encoded, 0, prefix.length);
        System.arraycopy(raw, 0, encoded, prefix.length, raw.length);
        return new X509EncodedKeySpec(encoded);
    }
}
