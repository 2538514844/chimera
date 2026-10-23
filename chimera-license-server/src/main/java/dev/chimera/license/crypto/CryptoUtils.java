package dev.chimera.license.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * All cryptography used by the license server, implemented with JDK 17 built-ins only
 * (X25519, Ed25519, HKDF-SHA256, AES-256-GCM, PBKDF2-HMAC-SHA256). The wire-level canonical
 * strings are defined in docs/AUTH-V2-PROTOCOL.md and must stay byte-identical to the client.
 */
public final class CryptoUtils {

    public static final int NONCE_16 = 16;
    public static final int GCM_NONCE_12 = 12;
    public static final int KEY_32 = 32;
    public static final int PBKDF2_ITERATIONS = 210_000;

    private static final byte[] ED25519_SPKI_PREFIX = {
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
    };
    private static final byte[] X25519_SPKI_PREFIX = {
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00
    };
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private CryptoUtils() {
    }

    // ---------------------------------------------------------------- encoding / random

    public static byte[] random(int length) {
        byte[] out = new byte[length];
        RANDOM.nextBytes(out);
        return out;
    }

    public static String b64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] unb64(String value) {
        return Base64.getDecoder().decode(value);
    }

    public static String hex(byte[] data) {
        char[] out = new char[data.length * 2];
        for (int i = 0; i < data.length; i++) {
            int value = data[i] & 0xff;
            out[i * 2] = HEX[value >>> 4];
            out[i * 2 + 1] = HEX[value & 0xf];
        }
        return new String(out);
    }

    public static byte[] sha256(byte[]... parts) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (byte[] part : parts) {
                if (part != null) {
                    digest.update(part);
                }
            }
            return digest.digest();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) {
            return false;
        }
        int difference = 0;
        for (int i = 0; i < a.length; i++) {
            difference |= a[i] ^ b[i];
        }
        return difference == 0;
    }

    // ---------------------------------------------------------------- HKDF / AES-GCM

    /** RFC 5869 HKDF-SHA256 (extract + expand). */
    public static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int length) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(salt == null || salt.length == 0 ? new byte[32] : salt, "HmacSHA256"));
            byte[] prk = mac.doFinal(ikm);
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            ByteArrayOutputStream out = new ByteArrayOutputStream(length);
            byte[] previous = new byte[0];
            int counter = 1;
            while (out.size() < length) {
                mac.update(previous);
                if (info != null) {
                    mac.update(info);
                }
                mac.update((byte) counter);
                previous = mac.doFinal();
                out.write(previous, 0, Math.min(previous.length, length - out.size()));
                counter++;
            }
            Arrays.fill(prk, (byte) 0);
            return out.toByteArray();
        } catch (Exception e) {
            throw new IllegalStateException("HKDF failed", e);
        }
    }

    /** AES-256-GCM encryption, returns {@code ciphertext || tag}. */
    public static byte[] aesGcmEncrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new IllegalStateException("AES-GCM encrypt failed", e);
        }
    }

    public static byte[] aesGcmDecrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] aad) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new IllegalStateException("AES-GCM decrypt failed", e);
        }
    }

    // ---------------------------------------------------------------- X25519

    public static KeyPair x25519KeyPair() {
        try {
            return KeyPairGenerator.getInstance("X25519").generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("X25519 unavailable", e);
        }
    }

    public static byte[] rawX25519(PublicKey publicKey) {
        byte[] encoded = publicKey.getEncoded();
        byte[] raw = new byte[32];
        System.arraycopy(encoded, encoded.length - 32, raw, 0, 32);
        return raw;
    }

    public static PublicKey x25519PublicKey(byte[] raw) {
        try {
            return KeyFactory.getInstance("X25519")
                    .generatePublic(new X509EncodedKeySpec(concat(X25519_SPKI_PREFIX, raw)));
        } catch (Exception e) {
            throw new IllegalArgumentException("invalid X25519 public key", e);
        }
    }

    public static byte[] x25519(PrivateKey privateKey, byte[] peerRawPublicKey) {
        try {
            KeyAgreement agreement = KeyAgreement.getInstance("X25519");
            agreement.init(privateKey);
            agreement.doPhase(x25519PublicKey(peerRawPublicKey), true);
            return agreement.generateSecret();
        } catch (Exception e) {
            throw new IllegalArgumentException("X25519 agreement failed", e);
        }
    }

    public static byte[] concat(byte[] first, byte[] second) {
        byte[] out = new byte[first.length + second.length];
        System.arraycopy(first, 0, out, 0, first.length);
        System.arraycopy(second, 0, out, first.length, second.length);
        return out;
    }

    // ---------------------------------------------------------------- Ed25519

    public static KeyPair ed25519KeyPair() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Ed25519 unavailable", e);
        }
    }

    public static byte[] rawEd25519(PublicKey publicKey) {
        byte[] encoded = publicKey.getEncoded();
        byte[] raw = new byte[32];
        System.arraycopy(encoded, encoded.length - 32, raw, 0, 32);
        return raw;
    }

    public static PublicKey ed25519PublicKey(byte[] raw) {
        try {
            return KeyFactory.getInstance("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(concat(ED25519_SPKI_PREFIX, raw)));
        } catch (Exception e) {
            throw new IllegalArgumentException("invalid Ed25519 public key", e);
        }
    }

    public static byte[] ed25519Sign(PrivateKey privateKey, byte[] message) {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(privateKey);
            signature.update(message);
            return signature.sign();
        } catch (Exception e) {
            throw new IllegalStateException("Ed25519 sign failed", e);
        }
    }

    public static boolean ed25519Verify(PublicKey publicKey, byte[] message, byte[] signature) {
        try {
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(publicKey);
            verifier.update(message);
            return verifier.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    public static PrivateKey privateKeyFromPkcs8(byte[] encoded) {
        try {
            return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(encoded));
        } catch (Exception e) {
            throw new IllegalStateException("invalid Ed25519 private key", e);
        }
    }

    // ---------------------------------------------------------------- PBKDF2 password hashing

    public static String hashPassword(String password) {
        byte[] salt = random(16);
        byte[] hash = pbkdf2(password, salt, PBKDF2_ITERATIONS);
        return "pbkdf2$" + PBKDF2_ITERATIONS + "$" + b64(salt) + "$" + b64(hash);
    }

    public static boolean verifyPassword(String password, String stored) {
        if (password == null || stored == null) {
            return false;
        }
        String[] parts = stored.split("\\$");
        if (parts.length != 4 || !"pbkdf2".equals(parts[0])) {
            return false;
        }
        try {
            int iterations = Integer.parseInt(parts[1]);
            byte[] salt = unb64(parts[2]);
            byte[] expected = unb64(parts[3]);
            byte[] actual = pbkdf2(password, salt, iterations);
            return constantTimeEquals(expected, actual);
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static byte[] pbkdf2(String password, byte[] salt, int iterations) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, 256);
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("PBKDF2 failed", e);
        }
    }

    // ---------------------------------------------------------------- per-account content key (B-Full lite)

    /** Domain-separation salt for the product MasterKey -> UserContentKey HKDF. */
    public static final byte[] USER_CONTENT_KEY_SALT =
            "chimera/uck/v1".getBytes(StandardCharsets.UTF_8);

    /**
     * Derives the per-account/per-device UserContentKey delivered inside {@code wrapped_ck}:
     *
     * <pre>
     * user_key = HKDF-SHA256(
     *     ikm  = MasterKey (32B, server-side only, never leaves the server),
     *     salt = UTF8("chimera/uck/v1"),
     *     info = BE64(account_id) || UTF8(hwid),
     *     L    = 32)
     * </pre>
     *
     * The requirement that both sides derive identical bytes makes this a wire contract, not an
     * implementation detail: the native client must implement exactly this formula.
     */
    public static byte[] deriveUserContentKey(byte[] masterKey, long accountId, String hwid) {
        if (masterKey == null || masterKey.length != KEY_32) {
            throw new IllegalArgumentException("master key must be 32 bytes");
        }
        if (hwid == null || hwid.isEmpty()) {
            throw new IllegalArgumentException("hwid must not be empty");
        }
        byte[] hwidBytes = hwid.getBytes(StandardCharsets.UTF_8);
        byte[] info = new byte[8 + hwidBytes.length];
        ByteBuffer.wrap(info).putLong(accountId);
        System.arraycopy(hwidBytes, 0, info, 8, hwidBytes.length);
        return hkdf(masterKey, USER_CONTENT_KEY_SALT, info, KEY_32);
    }

    /**
     * Risk-control poison transform: rotate the UserContentKey one byte to the left
     * ({@code poisoned[i] = key[(i + 1) % 32]}). The poisoned key has the same type/length and
     * travels inside an otherwise normally signed response, but it cannot decrypt content that
     * was encrypted with the legitimate UserContentKey.
     */
    public static byte[] poisonUserContentKey(byte[] userContentKey) {
        if (userContentKey == null || userContentKey.length != KEY_32) {
            throw new IllegalArgumentException("user content key must be 32 bytes");
        }
        byte[] poisoned = new byte[userContentKey.length];
        for (int i = 0; i < poisoned.length; i++) {
            poisoned[i] = userContentKey[(i + 1) % userContentKey.length];
        }
        return poisoned;
    }

    // ---------------------------------------------------------------- ResourceKey envelope (KI-28)

    /** Domain separation for wrapping the long-lived ResourceKey with a per-device UserContentKey. */
    public static final byte[] RESOURCE_WRAP_INFO =
            "chimera/resource-wrap/v1".getBytes(StandardCharsets.UTF_8);

    /**
     * Envelope key for {@code resource_ck}:
     * {@code HKDF-SHA256(ikm=UserContentKey, salt=32 zero bytes, info=UTF8("chimera/resource-wrap/v1"), L=32)}.
     * The client must use the UserContentKey it just unwrapped from {@code wrapped_ck}.
     */
    public static byte[] resourceWrapKey(byte[] userContentKey) {
        if (userContentKey == null || userContentKey.length != KEY_32) {
            throw new IllegalArgumentException("user content key must be 32 bytes");
        }
        return hkdf(userContentKey, null, RESOURCE_WRAP_INFO, KEY_32);
    }

    /** AAD binding the ResourceKey envelope to the account and device. */
    public static byte[] resourceAad(String account, String hwid) {
        return ("chimera-resource/v1|" + account + "|" + hwid)
                .getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Risk-control poison transform for the ResourceKey (same byte rotation as the UserContentKey):
     * {@code poisoned[i] = key[(i + 1) % 32]}.
     */
    public static byte[] poisonResourceKey(byte[] resourceKey) {
        return poisonUserContentKey(resourceKey);
    }

    // ---------------------------------------------------------------- canonical signed payloads

    /**
     * Canonical activation transcript (v3 + KI-28 resource envelope): exact key order, no whitespace.
     * {@code resource_ck} is inserted between {@code issued_at} and {@code sequence} (alphabetical order).
     */
    public static String canonicalActivate(long expiresAt, long issuedAt, long sequence,
                                           String serverEphemeralPub, String serverNonce,
                                           String token, String wrappedCk, String resourceCk) {
        return "{\"expires_at\":" + expiresAt
                + ",\"issued_at\":" + issuedAt
                + ",\"resource_ck\":\"" + resourceCk
                + "\",\"sequence\":" + sequence
                + ",\"server_ephemeral_pub\":\"" + serverEphemeralPub
                + "\",\"server_nonce\":\"" + serverNonce
                + "\",\"token\":\"" + token
                + "\",\"wrapped_ck\":\"" + wrappedCk + "\"}";
    }

    /** Canonical heartbeat transcript (v3): token is signed, sequence prevents rollback. */
    public static String canonicalHeartbeat(long expiresAt, long issuedAt, long sequence,
                                            String serverNonce, String token) {
        return "{\"expires_at\":" + expiresAt
                + ",\"issued_at\":" + issuedAt
                + ",\"sequence\":" + sequence
                + ",\"server_nonce\":\"" + serverNonce
                + "\",\"token\":\"" + token + "\"}";
    }

    /** AAD binding a wrapped content key to the account and device. */
    public static byte[] wrapAad(String account, String hwid) {
        return ("chimera-wrap/v1|" + account + "|" + hwid).getBytes(StandardCharsets.UTF_8);
    }
}
