package dev.chimera.crypto;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Stateless AES-GCM / HKDF-SHA256 / SHA-256 / HMAC-SHA256 helpers.
 *
 * <p>All methods are thread safe: no mutable shared state is kept, and a fresh
 * {@link Cipher}/{@link Mac} instance is created per call. JCE failures are wrapped
 * in {@link IllegalStateException}; invalid arguments (bad key/nonce/length, bad hex)
 * raise {@link IllegalArgumentException}.</p>
 */
public final class Crypto {
    private static final String HMAC_SHA256 = "HmacSHA256";
    private static final String SHA_256 = "SHA-256";
    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final int SHA256_BYTES = 32;
    private static final int GCM_NONCE_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final int HKDF_MAX_LEN = 255 * SHA256_BYTES;

    private static final SecureRandom RNG = new SecureRandom();
    private static final byte[] EMPTY = new byte[0];
    private static final char[] LOWER_HEX = "0123456789abcdef".toCharArray();

    private Crypto() {
    }

    /**
     * RFC 5869 HKDF-SHA256 (extract-then-expand).
     *
     * @param ikm    input keying material (required)
     * @param salt   optional salt; {@code null} or empty means a zero-filled hash-length salt
     * @param info   optional context/application specific info
     * @param length output length in bytes, {@code 0 <= length <= 255 * 32}
     */
    public static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int length) {
        if (ikm == null) {
            throw new IllegalArgumentException("ikm must not be null");
        }
        if (length < 0 || length > HKDF_MAX_LEN) {
            throw new IllegalArgumentException("hkdf length must be in [0, " + HKDF_MAX_LEN + "]: " + length);
        }
        byte[] effectiveInfo = info == null ? EMPTY : info;

        // Extract: PRK = HMAC-SHA256(salt, IKM)
        byte[] effectiveSalt = (salt == null || salt.length == 0) ? new byte[SHA256_BYTES] : salt;
        byte[] prk = hmacSha256(effectiveSalt, ikm);

        // Expand: T(i) = HMAC-SHA256(PRK, T(i-1) || info || byte(i))
        byte[] okm = new byte[length];
        byte[] previous = EMPTY;
        int offset = 0;
        for (int counter = 1; offset < length; counter++) {
            Mac mac = newMac(prk);
            mac.update(previous);
            mac.update(effectiveInfo);
            mac.update((byte) counter);
            previous = mac.doFinal();
            int chunk = Math.min(previous.length, length - offset);
            System.arraycopy(previous, 0, okm, offset, chunk);
            offset += chunk;
        }
        Arrays.fill(prk, (byte) 0);
        return okm;
    }

    /** AES/GCM/NoPadding encryption with a 128-bit tag. Returns {@code ciphertext || tag}. */
    public static byte[] aesGcmEncrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad) {
        return gcm(Cipher.ENCRYPT_MODE, key, nonce, plaintext == null ? EMPTY : plaintext, aad);
    }

    /** AES/GCM/NoPadding decryption of {@code ciphertext || tag}. */
    public static byte[] aesGcmDecrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] aad) {
        if (ciphertext == null) {
            throw new IllegalArgumentException("ciphertext must not be null");
        }
        return gcm(Cipher.DECRYPT_MODE, key, nonce, ciphertext, aad);
    }

    private static byte[] gcm(int mode, byte[] key, byte[] nonce, byte[] input, byte[] aad) {
        validateAesKey(key);
        if (nonce == null || nonce.length != GCM_NONCE_BYTES) {
            throw new IllegalArgumentException("GCM nonce must be " + GCM_NONCE_BYTES + " bytes");
        }
        try {
            Cipher cipher = Cipher.getInstance(AES_GCM);
            cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, nonce));
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(input);
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("AES-GCM operation failed", ex);
        }
    }

    private static void validateAesKey(byte[] key) {
        if (key == null) {
            throw new IllegalArgumentException("key must not be null");
        }
        if (key.length != 16 && key.length != 24 && key.length != 32) {
            throw new IllegalArgumentException("AES key must be 16, 24 or 32 bytes: " + key.length);
        }
    }

    /** SHA-256 over the concatenation of {@code parts} (null parts are treated as empty). */
    public static byte[] sha256(byte[]... parts) {
        if (parts == null) {
            throw new IllegalArgumentException("parts must not be null");
        }
        try {
            MessageDigest digest = MessageDigest.getInstance(SHA_256);
            for (byte[] part : parts) {
                if (part != null) {
                    digest.update(part);
                }
            }
            return digest.digest();
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("SHA-256 unavailable", ex);
        }
    }

    /** HMAC-SHA256. */
    public static byte[] hmacSha256(byte[] key, byte[] data) {
        if (key == null) {
            throw new IllegalArgumentException("key must not be null");
        }
        Mac mac = newMac(key);
        return mac.doFinal(data == null ? EMPTY : data);
    }

    private static Mac newMac(byte[] key) {
        try {
            Mac mac = Mac.getInstance(HMAC_SHA256);
            mac.init(new SecretKeySpec(key, HMAC_SHA256));
            return mac;
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("HMAC-SHA256 failed", ex);
        }
    }

    /** Cryptographically strong random bytes. */
    public static byte[] random(int n) {
        if (n < 0) {
            throw new IllegalArgumentException("length must be >= 0: " + n);
        }
        byte[] out = new byte[n];
        RNG.nextBytes(out);
        return out;
    }

    /** Lowercase hexadecimal encoding. */
    public static String hex(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("data must not be null");
        }
        char[] out = new char[data.length * 2];
        for (int i = 0; i < data.length; i++) {
            int b = data[i] & 0xff;
            out[i * 2] = LOWER_HEX[b >>> 4];
            out[i * 2 + 1] = LOWER_HEX[b & 0x0f];
        }
        return new String(out);
    }

    /**
     * Hexadecimal decoding. Accepts upper and lower case digits, ignores whitespace,
     * and rejects odd digit counts or non-hex characters with {@link IllegalArgumentException}.
     */
    public static byte[] unhex(String hex) {
        if (hex == null) {
            throw new IllegalArgumentException("hex must not be null");
        }
        int digits = 0;
        for (int i = 0; i < hex.length(); i++) {
            if (!Character.isWhitespace(hex.charAt(i))) {
                digits++;
            }
        }
        if ((digits & 1) != 0) {
            throw new IllegalArgumentException("hex string must contain an even number of digits");
        }
        byte[] out = new byte[digits / 2];
        int high = -1;
        int index = 0;
        for (int i = 0; i < hex.length(); i++) {
            char c = hex.charAt(i);
            if (Character.isWhitespace(c)) {
                continue;
            }
            int value = hexValue(c);
            if (value < 0) {
                throw new IllegalArgumentException("invalid hex character '" + c + "' at index " + i);
            }
            if (high < 0) {
                high = value;
            } else {
                out[index++] = (byte) ((high << 4) | value);
                high = -1;
            }
        }
        return out;
    }

    private static int hexValue(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        return -1;
    }
}
