package dev.chimera.transform.payload;

import dev.chimera.crypto.Crypto;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** S5 payload packager: layout, key derivation, round-trip, tamper and entropy properties. */
class PayloadPackagerTest {

    private static final byte[] RESOURCE_KEY = Crypto.sha256("payload-test-key".getBytes(StandardCharsets.UTF_8));
    private static final byte[] OTHER_KEY = Crypto.sha256("other-key".getBytes(StandardCharsets.UTF_8));
    private static final byte[] ENV_SALT = Crypto.sha256("payload-env-salt".getBytes(StandardCharsets.UTF_8));
    private static final SecureRandom RANDOM = new SecureRandom();

    @Test
    void explicitPayloadRoundTrips() {
        byte[] dll = random(4096);
        byte[] payload = random(8 * 1024);

        byte[] packaged = PayloadPackager.appendTo(dll, payload, RESOURCE_KEY, ENV_SALT);

        assertTrue(PayloadPackager.verify(packaged));
        assertArrayEquals(payload, PayloadPackager.extract(packaged, RESOURCE_KEY, ENV_SALT));
        assertArrayEquals(dll, Arrays.copyOf(packaged, dll.length),
                "carrier DLL bytes must stay untouched and first");
    }

    @Test
    void nullPayloadEmbedsCarrierForSelfExtraction() {
        byte[] dll = random(2048);

        byte[] packaged = PayloadPackager.appendTo(dll, null, RESOURCE_KEY, ENV_SALT);

        assertTrue(PayloadPackager.verify(packaged));
        assertEquals(dll.length + dll.length + PayloadPackager.FOOTER_LENGTH, packaged.length);
        assertArrayEquals(dll, PayloadPackager.extract(packaged, RESOURCE_KEY, ENV_SALT));
    }

    @Test
    void emptyCarrierStillRoundTrips() {
        byte[] payload = random(512);

        byte[] packaged = PayloadPackager.appendTo(new byte[0], payload, RESOURCE_KEY, ENV_SALT);

        assertTrue(PayloadPackager.verify(packaged));
        PayloadPackager.OverlayLayout layout = PayloadPackager.locate(packaged);
        assertNotNull(layout);
        assertEquals(0, layout.carrierLength());
        assertArrayEquals(payload, PayloadPackager.extract(packaged, RESOURCE_KEY, ENV_SALT));
    }

    @Test
    void overlayIsLocatedFromTheTailOnly() {
        byte[] dll = random(1000);
        byte[] payload = random(777);
        byte[] packaged = PayloadPackager.appendTo(dll, payload, RESOURCE_KEY, ENV_SALT);
        int footer = packaged.length - PayloadPackager.FOOTER_LENGTH;

        PayloadPackager.OverlayLayout layout = PayloadPackager.locate(packaged);

        assertNotNull(layout);
        assertEquals(dll.length, layout.carrierLength());
        assertEquals(dll.length, layout.ciphertextOffset());
        assertEquals(payload.length, layout.ciphertextLength());
        assertEquals(packaged.length, layout.totalLength());
        assertEquals(packaged.length - footer, PayloadPackager.FOOTER_LENGTH);
        assertArrayEquals(new byte[]{'C', 'H', 'P', 'Y'}, Arrays.copyOfRange(packaged,
                footer + PayloadPackager.FOOTER_MAGIC_OFFSET,
                footer + PayloadPackager.FOOTER_MAGIC_OFFSET + 4));
        assertEquals(1, (packaged[footer + PayloadPackager.FOOTER_VERSION_OFFSET] & 0xff)
                | ((packaged[footer + PayloadPackager.FOOTER_VERSION_OFFSET + 1] & 0xff) << 8)
                | ((packaged[footer + PayloadPackager.FOOTER_VERSION_OFFSET + 2] & 0xff) << 16)
                | ((packaged[footer + PayloadPackager.FOOTER_VERSION_OFFSET + 3] & 0xff) << 24));
        long storedLength = 0L;
        for (int i = 0; i < 8; i++) {
            storedLength |= (long) (packaged[footer + PayloadPackager.FOOTER_LENGTH_OFFSET + i] & 0xff)
                    << (8 * i);
        }
        assertEquals(payload.length, storedLength);
    }

    @Test
    void ciphertextEntropyExceedsThreshold() {
        byte[] packaged = PayloadPackager.appendTo(random(4096), random(32 * 1024),
                RESOURCE_KEY, ENV_SALT);
        PayloadPackager.OverlayLayout layout = PayloadPackager.locate(packaged);
        assertNotNull(layout);
        byte[] ciphertext = Arrays.copyOfRange(packaged, layout.ciphertextOffset(),
                layout.ciphertextOffset() + layout.ciphertextLength());

        double entropy = shannonEntropy(ciphertext);

        assertTrue(entropy > 7.9, "ciphertext entropy must be > 7.9, was " + entropy);
    }

    @Test
    void tamperedCiphertextFailsAuthentication() {
        byte[] packaged = PayloadPackager.appendTo(random(1024), random(2048),
                RESOURCE_KEY, ENV_SALT);
        PayloadPackager.OverlayLayout layout = PayloadPackager.locate(packaged);
        assertNotNull(layout);
        packaged[layout.ciphertextOffset() + 7] ^= 0x01;

        assertTrue(PayloadPackager.verify(packaged), "structure is still valid");
        assertThrows(IllegalArgumentException.class,
                () -> PayloadPackager.extract(packaged, RESOURCE_KEY, ENV_SALT),
                "GCM must reject modified ciphertext");
    }

    @Test
    void tamperedFooterMagicIsRejected() {
        byte[] packaged = PayloadPackager.appendTo(random(256), random(256),
                RESOURCE_KEY, ENV_SALT);
        int magic = packaged.length - PayloadPackager.FOOTER_LENGTH
                + PayloadPackager.FOOTER_MAGIC_OFFSET;
        packaged[magic] = 'X';

        assertFalse(PayloadPackager.verify(packaged));
        assertThrows(IllegalArgumentException.class,
                () -> PayloadPackager.extract(packaged, RESOURCE_KEY, ENV_SALT));
    }

    @Test
    void tamperedVersionIsRejected() {
        byte[] packaged = PayloadPackager.appendTo(random(256), random(256),
                RESOURCE_KEY, ENV_SALT);
        int version = packaged.length - PayloadPackager.FOOTER_LENGTH
                + PayloadPackager.FOOTER_VERSION_OFFSET;
        packaged[version] = 2;

        assertFalse(PayloadPackager.verify(packaged));
    }

    @Test
    void payloadLengthBeyondTheFileIsRejected() {
        byte[] packaged = PayloadPackager.appendTo(random(256), random(256),
                RESOURCE_KEY, ENV_SALT);
        int lengthOffset = packaged.length - PayloadPackager.FOOTER_LENGTH
                + PayloadPackager.FOOTER_LENGTH_OFFSET;
        long tooLarge = packaged.length;
        for (int i = 0; i < 8; i++) {
            packaged[lengthOffset + i] = (byte) (tooLarge >>> (8 * i));
        }

        assertFalse(PayloadPackager.verify(packaged));
    }

    @Test
    void truncatedOverlayIsRejected() {
        byte[] packaged = PayloadPackager.appendTo(random(256), random(256),
                RESOURCE_KEY, ENV_SALT);

        assertFalse(PayloadPackager.verify(Arrays.copyOf(packaged, packaged.length - 1)));
        assertFalse(PayloadPackager.verify(Arrays.copyOf(packaged, PayloadPackager.FOOTER_LENGTH - 1)));
    }

    @Test
    void wrongKeyFailsAuthentication() {
        byte[] packaged = PayloadPackager.appendTo(random(256), random(1024),
                RESOURCE_KEY, ENV_SALT);

        assertThrows(IllegalArgumentException.class,
                () -> PayloadPackager.extract(packaged, OTHER_KEY, ENV_SALT));
        assertThrows(IllegalArgumentException.class,
                () -> PayloadPackager.extract(packaged, RESOURCE_KEY, new byte[]{1, 2, 3}));
    }

    @Test
    void deriveKeyMatchesDomainSeparatedHkdf() {
        byte[] expected = Crypto.hkdf(RESOURCE_KEY, ENV_SALT,
                "chimera/v1/payload".getBytes(StandardCharsets.UTF_8), 32);

        assertArrayEquals(expected, PayloadPackager.deriveKey(RESOURCE_KEY, ENV_SALT));
        assertFalse(Arrays.equals(PayloadPackager.deriveKey(RESOURCE_KEY, null),
                PayloadPackager.deriveKey(RESOURCE_KEY, ENV_SALT)));
    }

    @Test
    void rejectsInvalidArguments() {
        byte[] dll = random(64);
        byte[] payload = random(64);

        assertThrows(IllegalArgumentException.class,
                () -> PayloadPackager.appendTo(null, payload, RESOURCE_KEY, ENV_SALT));
        assertThrows(IllegalArgumentException.class,
                () -> PayloadPackager.appendTo(dll, new byte[0], RESOURCE_KEY, ENV_SALT));
        assertThrows(IllegalArgumentException.class,
                () -> PayloadPackager.appendTo(dll, payload, new byte[16], ENV_SALT));
        assertThrows(IllegalArgumentException.class,
                () -> PayloadPackager.appendTo(dll, payload, null, ENV_SALT));
        assertThrows(IllegalArgumentException.class,
                () -> PayloadPackager.appendTo(dll, payload, RESOURCE_KEY, new byte[65]));
        assertThrows(IllegalArgumentException.class,
                () -> PayloadPackager.deriveKey(RESOURCE_KEY, new byte[65]));
    }

    @Test
    void verifyRejectsNullAndShortInput() {
        assertFalse(PayloadPackager.verify(null));
        assertFalse(PayloadPackager.verify(new byte[0]));
        assertFalse(PayloadPackager.verify(new byte[PayloadPackager.FOOTER_LENGTH - 1]));
        assertNull(PayloadPackager.locate(null));
    }

    @Test
    void freshNoncePerPackage() {
        byte[] dll = random(128);
        byte[] payload = random(128);

        byte[] first = PayloadPackager.appendTo(dll, payload, RESOURCE_KEY, ENV_SALT);
        byte[] second = PayloadPackager.appendTo(dll, payload, RESOURCE_KEY, ENV_SALT);
        PayloadPackager.OverlayLayout firstLayout = PayloadPackager.locate(first);
        PayloadPackager.OverlayLayout secondLayout = PayloadPackager.locate(second);

        assertNotNull(firstLayout);
        assertNotNull(secondLayout);
        assertFalse(Arrays.equals(firstLayout.nonce(), secondLayout.nonce()));
        byte[] firstCiphertext = Arrays.copyOfRange(first, firstLayout.ciphertextOffset(),
                firstLayout.ciphertextOffset() + firstLayout.ciphertextLength());
        byte[] secondCiphertext = Arrays.copyOfRange(second, secondLayout.ciphertextOffset(),
                secondLayout.ciphertextOffset() + secondLayout.ciphertextLength());
        assertFalse(Arrays.equals(firstCiphertext, secondCiphertext));
        assertArrayEquals(payload, PayloadPackager.extract(first, RESOURCE_KEY, ENV_SALT));
        assertArrayEquals(payload, PayloadPackager.extract(second, RESOURCE_KEY, ENV_SALT));
    }

    private static byte[] random(int length) {
        byte[] out = new byte[length];
        RANDOM.nextBytes(out);
        return out;
    }

    private static double shannonEntropy(byte[] data) {
        int[] counts = new int[256];
        for (byte value : data) {
            counts[value & 0xff]++;
        }
        double entropy = 0.0;
        for (int count : counts) {
            if (count == 0) {
                continue;
            }
            double probability = count / (double) data.length;
            entropy -= probability * (Math.log(probability) / Math.log(2.0));
        }
        return entropy;
    }
}
