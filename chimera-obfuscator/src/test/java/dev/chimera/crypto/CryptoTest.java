package dev.chimera.crypto;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CryptoTest {

    private static byte[] repeat(byte value, int count) {
        byte[] out = new byte[count];
        java.util.Arrays.fill(out, value);
        return out;
    }

    @Test
    void hkdfMatchesRfc5869TestCase1() {
        // RFC 5869 A.1: IKM = 0x0b x 22, salt = 000102...0c, info = f0f1...f9, L = 42.
        byte[] ikm = repeat((byte) 0x0b, 22);
        byte[] salt = Crypto.unhex("000102030405060708090a0b0c");
        byte[] info = Crypto.unhex("f0f1f2f3f4f5f6f7f8f9");

        byte[] okm = Crypto.hkdf(ikm, salt, info, 42);

        assertEquals(42, okm.length);
        assertEquals("3cb25f25faacd57a90434f64d0362f2a"
                        + "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                        + "34007208d5b887185865",
                Crypto.hex(okm));
    }

    @Test
    void hkdfIsDeterministicAndSupportsNullSaltAndInfo() {
        byte[] ikm = "input keying material".getBytes(StandardCharsets.UTF_8);
        byte[] a = Crypto.hkdf(ikm, null, null, 32);
        byte[] b = Crypto.hkdf(ikm, new byte[32], new byte[0], 32);
        assertArrayEquals(a, b);

        byte[] longer = Crypto.hkdf(ikm, null, null, 64);
        assertArrayEquals(a, java.util.Arrays.copyOf(longer, 32));
        assertArrayEquals(new byte[0], Crypto.hkdf(ikm, null, null, 0));
    }

    @Test
    void hkdfRejectsInvalidLengths() {
        byte[] ikm = new byte[16];
        assertThrows(IllegalArgumentException.class, () -> Crypto.hkdf(ikm, null, null, -1));
        assertThrows(IllegalArgumentException.class, () -> Crypto.hkdf(ikm, null, null, 255 * 32 + 1));
        assertEquals(255 * 32, Crypto.hkdf(ikm, null, null, 255 * 32).length);
    }

    @Test
    void aesGcmRoundTripWithAndWithoutAad() {
        byte[] key = Crypto.random(32);
        byte[] nonce = Crypto.random(12);
        byte[] plaintext = "Chimera 混淆器 \u2603".getBytes(StandardCharsets.UTF_8);
        byte[] aad = "chimera/v1/str/7".getBytes(StandardCharsets.UTF_8);

        byte[] withAad = Crypto.aesGcmEncrypt(key, nonce, plaintext, aad);
        assertEquals(plaintext.length + 16, withAad.length);
        assertArrayEquals(plaintext, Crypto.aesGcmDecrypt(key, nonce, withAad, aad));

        byte[] noAad = Crypto.aesGcmEncrypt(key, nonce, plaintext, null);
        assertArrayEquals(plaintext, Crypto.aesGcmDecrypt(key, nonce, noAad, null));

        byte[] empty = Crypto.aesGcmEncrypt(key, nonce, new byte[0], aad);
        assertEquals(16, empty.length);
        assertArrayEquals(new byte[0], Crypto.aesGcmDecrypt(key, nonce, empty, aad));
    }

    @Test
    void aesGcmRejectsTamperedInput() {
        byte[] key = Crypto.random(32);
        byte[] nonce = Crypto.random(12);
        byte[] plaintext = "tamper me".getBytes(StandardCharsets.UTF_8);
        byte[] aad = "aad".getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = Crypto.aesGcmEncrypt(key, nonce, plaintext, aad);

        byte[] badTag = ciphertext.clone();
        badTag[badTag.length - 1] ^= 0x01;
        assertThrows(IllegalStateException.class, () -> Crypto.aesGcmDecrypt(key, nonce, badTag, aad));

        byte[] badBody = ciphertext.clone();
        badBody[0] ^= 0x01;
        assertThrows(IllegalStateException.class, () -> Crypto.aesGcmDecrypt(key, nonce, badBody, aad));

        assertThrows(IllegalStateException.class,
                () -> Crypto.aesGcmDecrypt(key, nonce, ciphertext, "other".getBytes(StandardCharsets.UTF_8)));
        assertThrows(IllegalStateException.class,
                () -> Crypto.aesGcmDecrypt(Crypto.random(32), nonce, ciphertext, aad));
        assertThrows(IllegalStateException.class,
                () -> Crypto.aesGcmDecrypt(key, nonce, new byte[8], aad));
    }

    @Test
    void aesGcmRejectsInvalidParameters() {
        byte[] nonce = Crypto.random(12);
        assertThrows(IllegalArgumentException.class,
                () -> Crypto.aesGcmEncrypt(new byte[20], nonce, new byte[1], null));
        assertThrows(IllegalArgumentException.class,
                () -> Crypto.aesGcmEncrypt(new byte[32], new byte[11], new byte[1], null));
        assertThrows(IllegalArgumentException.class,
                () -> Crypto.aesGcmEncrypt(null, nonce, new byte[1], null));
        assertThrows(IllegalArgumentException.class,
                () -> Crypto.aesGcmDecrypt(new byte[16], nonce, null, null));
    }

    @Test
    void sha256MatchesKnownVectors() {
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                Crypto.hex(Crypto.sha256("abc".getBytes(StandardCharsets.US_ASCII))));
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                Crypto.hex(Crypto.sha256()));
    }

    @Test
    void sha256ConcatenatesParts() {
        byte[] oneShot = Crypto.sha256("hello world".getBytes(StandardCharsets.UTF_8));
        byte[] split = Crypto.sha256("hello ".getBytes(StandardCharsets.UTF_8),
                "world".getBytes(StandardCharsets.UTF_8));
        assertArrayEquals(oneShot, split);
        assertArrayEquals(oneShot, Crypto.sha256("hello ".getBytes(StandardCharsets.UTF_8), null,
                "world".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void hmacSha256MatchesKnownVector() {
        // RFC 4231 test case 1.
        byte[] key = repeat((byte) 0x0b, 20);
        byte[] mac = Crypto.hmacSha256(key, "Hi There".getBytes(StandardCharsets.US_ASCII));
        assertEquals("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                Crypto.hex(mac));
    }

    @Test
    void randomRespectsLength() {
        assertEquals(0, Crypto.random(0).length);
        assertEquals(32, Crypto.random(32).length);
        assertThrows(IllegalArgumentException.class, () -> Crypto.random(-1));
        assertArrayEquals(new byte[0], Crypto.random(0));
        // Two 32-byte draws colliding would be a 2^-256 event.
        assertTrue(!java.util.Arrays.equals(Crypto.random(32), Crypto.random(32)));
    }

    @Test
    void hexAndUnhexRoundTrip() {
        byte[] data = new byte[]{0x00, 0x01, (byte) 0xab, (byte) 0xff};
        assertEquals("0001abff", Crypto.hex(data));
        assertArrayEquals(data, Crypto.unhex("0001abff"));
        assertArrayEquals(data, Crypto.unhex("00 01 AB FF"));
        assertArrayEquals(data, Crypto.unhex("  0 0 0 1 a B f F  "));
        assertArrayEquals(new byte[0], Crypto.unhex(""));
        assertArrayEquals(new byte[0], Crypto.unhex("   "));
    }

    @Test
    void unhexRejectsInvalidInput() {
        assertThrows(IllegalArgumentException.class, () -> Crypto.unhex(null));
        assertThrows(IllegalArgumentException.class, () -> Crypto.unhex("abc"));
        assertThrows(IllegalArgumentException.class, () -> Crypto.unhex("0x00"));
        assertThrows(IllegalArgumentException.class, () -> Crypto.unhex("zz"));
    }

    @Test
    void staticHelpersAreThreadSafe() throws Exception {
        byte[] message = "concurrent".getBytes(StandardCharsets.UTF_8);
        byte[] expected = Crypto.sha256(message);
        byte[] key = Crypto.random(32);
        byte[] expectedMac = Crypto.hmacSha256(key, message);
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            List<Future<byte[]>> results = new ArrayList<>();
            for (int i = 0; i < 64; i++) {
                results.add(pool.submit(() -> Crypto.sha256(message)));
                results.add(pool.submit(() -> Crypto.hmacSha256(key, message)));
            }
            for (int i = 0; i < results.size(); i++) {
                assertArrayEquals(i % 2 == 0 ? expected : expectedMac, results.get(i).get());
            }
        } finally {
            pool.shutdownNow();
        }
    }
}
