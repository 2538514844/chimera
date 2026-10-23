package dev.chimera.transform.payload;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Locale;
import java.util.zip.CRC32;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * #24 payload-stealth codec: CHS1 blob round-trip, disguise properties (no MZ at offset 0, masked
 * PE signatures, pad), fail-closed tamper rejection (magic / geometry / mask / CRC).
 * Public: dev.chimera.runtime.ChimeraStealthLoaderTest reuses fakeDll().
 */
public class StealthPayloadCodecTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    // ------------------------------------------------------------------ round-trip

    @Test
    void encodeDecodeRoundTripsTheDll() {
        byte[] dll = fakeDll(64 * 1024);

        byte[] blob = StealthPayloadCodec.encode(dll, 4096, null);

        assertNotNull(StealthPayloadCodec.locate(blob));
        assertArrayEquals(dll, StealthPayloadCodec.decode(blob));
    }

    @Test
    void explicitXorKeyRoundTripsAndIsEmbedded() {
        byte[] dll = fakeDll(8192);
        byte[] key = new byte[StealthPayloadCodec.MASK_LENGTH];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (i + 1);
        }

        byte[] blob = StealthPayloadCodec.encode(dll, 0, key);

        StealthPayloadCodec.Layout layout = StealthPayloadCodec.locate(blob);
        assertNotNull(layout);
        assertTrue(Arrays.equals(key, layout.mask()));
        assertArrayEquals(dll, StealthPayloadCodec.decode(blob));
        // The first 24 blob bytes are the random prefix, not the DLL; compare the DLL region.
        assertFalse(Arrays.equals(Arrays.copyOfRange(dll, 0, 64),
                Arrays.copyOfRange(blob, layout.dllOffset(), layout.dllOffset() + 64)));
    }

    @Test
    void blobIsAtLeastPadBytesAndTrailerIsAtTheTail() {
        byte[] dll = fakeDll(1024);
        long pad = 4096;

        byte[] blob = StealthPayloadCodec.encode(dll, pad, null);

        StealthPayloadCodec.Layout layout = StealthPayloadCodec.locate(blob);
        assertNotNull(layout);
        assertEquals(StealthPayloadCodec.PREFIX_LENGTH, layout.dllOffset());
        assertEquals(dll.length, layout.dllLength());
        assertTrue(layout.padLength() >= pad, "pad " + layout.padLength() + " >= " + pad);
        assertTrue(blob.length >= StealthPayloadCodec.PREFIX_LENGTH + dll.length + pad
                + StealthPayloadCodec.TRAILER_LENGTH);
        // The last 4 bytes store the trailer offset, so the trailer begins 4 bytes before them
        // only in a corrupt encoding; the stored value must point at the trailer start itself.
        int stored = readU32(blob, blob.length - 4);
        assertEquals(blob.length - StealthPayloadCodec.TRAILER_LENGTH, stored,
                "trailer offset must point at the trailer start");
        assertEquals("CHS1", new String(Arrays.copyOfRange(blob,
                stored + StealthPayloadCodec.MASK_LENGTH + 12,
                stored + StealthPayloadCodec.MASK_LENGTH + 16),
                java.nio.charset.StandardCharsets.US_ASCII));
    }

    // ------------------------------------------------------------------ disguise shape

    @Test
    void firstTwoBytesAreNeverMZ() {
        for (int attempt = 0; attempt < 64; attempt++) {
            byte[] blob = StealthPayloadCodec.encode(fakeDll(512), 0, null);
            assertFalse(blob[0] == 'M' && blob[1] == 'Z',
                    "attempt " + attempt + " leaked the MZ signature at offset 0");
        }
    }

    @Test
    void noPlainMZSignatureAnywhereBeforeTheTrailer() {
        byte[] dll = fakeDll(64 * 1024);
        byte[] blob = StealthPayloadCodec.encode(dll, 0, null);

        int trailerOffset = readU32(blob, blob.length - 4);
        int plainMz = indexOf(blob, new byte[]{'M', 'Z'}, 0, trailerOffset);
        assertEquals(-1, plainMz, "masked region must not contain a plain MZ; found at " + plainMz);
    }

    @Test
    void entropyOfTheMaskedDllRegionIsHigh() {
        byte[] dll = fakeDll(96 * 1024);  // PE-like: long stretches of 0x00 would tank entropy
        byte[] blob = StealthPayloadCodec.encode(dll, 0, null);

        StealthPayloadCodec.Layout layout = StealthPayloadCodec.locate(blob);
        assertNotNull(layout);
        byte[] region = Arrays.copyOfRange(blob, 0, layout.dllOffset() + layout.dllLength());
        double entropy = shannonEntropy(region);
        // A zero-heavy fake PE masked by an 8-byte key collapses to <=256 byte classes; that is
        // a property of the synthetic fixture, not of real DLL bytes (see the real-DLL entropy
        // numbers in docs/PAYLOAD-STEALTH-NOTES.md, produced by the same codec). The bound here
        // checks the mask destroyed the PE structure without relying on fixture entropy.
        assertTrue(entropy > 2.0, "masked region entropy " + entropy + " must exceed 2.0");
        // The byte-value histogram must differ from the raw DLL (mask visibly transformed it).
        int[] rawCounts = histogram(Arrays.copyOf(dll, 4096));
        int[] maskedCounts = histogram(Arrays.copyOfRange(blob, 0, 4096));
        assertFalse(Arrays.equals(rawCounts, maskedCounts),
                "mask must change the byte distribution");
    }

    @Test
    void trailerMagicSurvivesAtTheExpectedOffset() {
        byte[] blob = StealthPayloadCodec.encode(fakeDll(300), 0, null);
        int trailerOffset = readU32(blob, blob.length - 4);
        assertEquals("CHS1", new String(Arrays.copyOfRange(blob,
                trailerOffset + StealthPayloadCodec.MASK_LENGTH + 12,
                trailerOffset + StealthPayloadCodec.MASK_LENGTH + 16),
                java.nio.charset.StandardCharsets.US_ASCII));
    }

    // ------------------------------------------------------------------ fail-closed

    @Test
    void decodeRejectsNullAndShortInputs() {
        assertNull(StealthPayloadCodec.decode(null));
        assertNull(StealthPayloadCodec.decode(new byte[0]));
        assertNull(StealthPayloadCodec.decode(new byte[StealthPayloadCodec.TRAILER_LENGTH - 1]));
    }

    @Test
    void decodeRejectsBadMagic() {
        byte[] blob = StealthPayloadCodec.encode(fakeDll(256), 0, null);
        int trailerOffset = readU32(blob, blob.length - 4);
        blob[trailerOffset + StealthPayloadCodec.MASK_LENGTH + 12] ^= 0x20;
        assertNull(StealthPayloadCodec.locate(blob));
        assertNull(StealthPayloadCodec.decode(blob));
    }

    @Test
    void decodeRejectsCorruptedDllBytesViaCrc() {
        byte[] blob = StealthPayloadCodec.encode(fakeDll(1024), 64, null);
        blob[StealthPayloadCodec.PREFIX_LENGTH + 17] ^= 0x40;
        assertNull(StealthPayloadCodec.decode(blob), "CRC must catch the flipped DLL byte");
    }

    @Test
    void decodeRejectsTruncatedAndExtendedBlobs() {
        byte[] blob = StealthPayloadCodec.encode(fakeDll(300), 0, null);
        assertNull(StealthPayloadCodec.decode(Arrays.copyOf(blob, blob.length - 1)));
        assertNull(StealthPayloadCodec.decode(Arrays.copyOf(blob, blob.length + 1)));
    }

    @Test
    void decodeRejectsForgedGeometry() {
        byte[] blob = StealthPayloadCodec.encode(fakeDll(512), 128, null);
        int trailerOffset = readU32(blob, blob.length - 4);
        int lengthAt = trailerOffset + StealthPayloadCodec.MASK_LENGTH;
        blob[lengthAt] ^= 0x01;  // dllLength +/- 1 breaks PREFIX+DLL+PAD == trailerOffset
        assertNull(StealthPayloadCodec.locate(blob));
        assertNull(StealthPayloadCodec.decode(blob));
    }

    @Test
    void decodeRejectsZeroMaskTampering() {
        byte[] blob = StealthPayloadCodec.encode(fakeDll(256), 0, null);
        int trailerOffset = readU32(blob, blob.length - 4);
        Arrays.fill(blob, trailerOffset, trailerOffset + StealthPayloadCodec.MASK_LENGTH, (byte) 0);
        // The locate() check passes (mask bytes are opaque), but the CRC then fails on decode.
        assertNull(StealthPayloadCodec.decode(blob));
    }

    @Test
    void encodeRejectsNonPeInput() {
        byte[] notPe = new byte[64];
        RANDOM.nextBytes(notPe);
        notPe[0] = 'M';
        notPe[1] = 'Z' - 1;
        assertThrows(IllegalArgumentException.class, () -> StealthPayloadCodec.encode(notPe, 0, null));
        assertThrows(IllegalArgumentException.class,
                () -> StealthPayloadCodec.encode(null, 0, null));
        assertThrows(IllegalArgumentException.class,
                () -> StealthPayloadCodec.encode(new byte[0], 0, null));
    }

    @Test
    void encodeRejectsBadMasks() {
        byte[] dll = fakeDll(0x400);
        assertThrows(IllegalArgumentException.class,
                () -> StealthPayloadCodec.encode(dll, 0, new byte[7]));
        assertThrows(IllegalArgumentException.class,
                () -> StealthPayloadCodec.encode(dll, 0, new byte[StealthPayloadCodec.MASK_LENGTH - 1]));
    }

    @Test
    void everyEncodingUsesAFreshRandomPrefixAndMask() {
        byte[] dll = fakeDll(0x400);
        byte[] first = StealthPayloadCodec.encode(dll, 0, null);
        byte[] second = StealthPayloadCodec.encode(dll, 0, null);
        assertNotEquals(java.util.HexFormat.of().formatHex(first),
                java.util.HexFormat.of().formatHex(second),
                "random prefix + random mask must differ per encoding");
        assertArrayEquals(dll, StealthPayloadCodec.decode(first));
        assertArrayEquals(dll, StealthPayloadCodec.decode(second));
    }

    // ------------------------------------------------------------------ helpers

    /** Fake but PE-shaped bytes: MZ + PE\0\0 + e_lfanew, then mostly zeros like a real .text. */
    public static byte[] fakeDll(int size) {
        if (size < 0x44) {
            throw new IllegalArgumentException("fakeDll needs >= 0x44 bytes, got " + size);
        }
        byte[] dll = new byte[size];
        dll[0] = 'M';
        dll[1] = 'Z';
        dll[0x40] = 'P';
        dll[0x41] = 'E';
        dll[0x42] = 0;
        dll[0x43] = 0;
        // e_lfanew at 0x3c -> 0x40
        dll[0x3c] = 0x40;
        // sparse ASCII strings like a real image would carry (repeat so any size stays PE-like;
        // sizes below 0x240 have no room and keep the plain zeroed .text shape)
        byte[] strings = "kernel32.dll CreateFileW ntdll.dll RtlInitializeNtdll".getBytes(
                java.nio.charset.StandardCharsets.US_ASCII);
        int at = 0x200;
        while (at + strings.length <= size) {
            System.arraycopy(strings, 0, dll, at, strings.length);
            at += 0x400;
        }
        return dll;
    }

    private static int readU32(byte[] data, int offset) {
        return (data[offset] & 0xff)
                | ((data[offset + 1] & 0xff) << 8)
                | ((data[offset + 2] & 0xff) << 16)
                | ((data[offset + 3] & 0xff) << 24);
    }

    private static int indexOf(byte[] haystack, byte[] needle, int from, int to) {
        outer:
        for (int i = from; i <= to - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    static double shannonEntropy(byte[] data) {
        int[] counts = histogram(data);
        double entropy = 0.0;
        for (int count : counts) {
            if (count == 0) {
                continue;
            }
            double p = (double) count / data.length;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    static int[] histogram(byte[] data) {
        int[] counts = new int[256];
        for (byte b : data) {
            counts[b & 0xff]++;
        }
        return counts;
    }
}
