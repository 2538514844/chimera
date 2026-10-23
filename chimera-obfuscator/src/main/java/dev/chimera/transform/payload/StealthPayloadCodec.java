package dev.chimera.transform.payload;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.zip.CRC32;

/**
 * S5 payload-stealth build side: encodes a native DLL into the disguised resource blob the
 * stealth loader materialises at runtime (Hachimi parity, docs/HACHIMI-ARCH-vs-CHIMERA.md §3).
 *
 * <p>The encoded blob is what ships inside the jar (resource name has no {@code .dll} suffix,
 * default {@code chimera/res/native.dat}). Layout (little-endian):</p>
 * <pre>
 * [prefix(24, random non-MZ bytes)][DLL bytes XOR-masked with key][random pad >= padBytes]
 * [8-byte random mask at trailerOffset+0]
 * [u32 dllLength        at trailerOffset+8]
 * [u32 padLength       at trailerOffset+12]
 * [u32 crc32(dllBytes)  at trailerOffset+16]
 * ["CHS1"               at trailerOffset+20]
 * [u32 trailerOffset    at trailerOffset+24]  (the final 4 bytes of the blob)
 * </pre>
 *
 * <p>Disguise properties, mirroring the Hachimi {@code PhantomShieldX64.diy} measurements:</p>
 * <ul>
 *   <li>the first two bytes are random and can never decode to {@code MZ}; the raw DLL header is
 *       pushed {@code PREFIX_LENGTH} bytes in (Hachimi hides MZ at offset ~66k; here it is bounded
 *       by the prefix plus the load-time reconstruction ordering),</li>
 *   <li>the DLL bytes are XOR-masked with a random 8-byte key (Hachimi used 0x01 on its ASCII
 *       region; masking the whole body here also destroys every embedded PE signature),</li>
 *   <li>a random tail pad keeps the resource at the requested size
 *       ({@code --payload-pad}, like the 47MB Hachimi blob),</li>
 *   <li>the 28-byte trailer is found from the tail (like {@link PayloadPackager}'s CHPY footer),
 *       so no MZ/PE structure is needed to locate anything.</li>
 * </ul>
 *
 * <p>Integrity: CRC-32 of the raw DLL bytes is stored in the trailer and re-verified by the
 * loader after reconstruction; a wrong magic, truncated blob, out-of-range geometry or CRC
 * mismatch fails closed (halt(4) semantics in the runtime loader). The mask key is random per
 * build and embedded in the trailer — the encoding is a disguise, not a secret; payload secrecy
 * is the CHPY overlay's job when {@code --payload-overlay} is used on top.</p>
 */
public final class StealthPayloadCodec {

    /** Trailer magic. */
    public static final String MAGIC = "CHS1";
    /** Random non-MZ prefix length. */
    public static final int PREFIX_LENGTH = 24;
    public static final int MASK_LENGTH = 64;
    public static final int TRAILER_LENGTH = MASK_LENGTH + 4 + 4 + 4 + 4 + 4;
    public static final int MAX_DLL_BYTES = 96 * 1024 * 1024;

    /** Default disguised resource name (no .dll suffix on purpose). */
    public static final String DEFAULT_RESOURCE_NAME = "chimera/res/native.dat";

    private static final byte[] MAGIC_BYTES = MAGIC.getBytes(StandardCharsets.US_ASCII);
    private static final SecureRandom RNG = new SecureRandom();

    private StealthPayloadCodec() {
    }

    /**
     * Encodes {@code dll} into a disguised resource blob.
     *
     * @param dll      raw DLL bytes; the first two bytes must be the {@code MZ} DOS signature
     *                 (a real PE file, fail-closed otherwise)
     * @param padBytes minimum random pad appended after the masked DLL ({@code --payload-pad});
     *                 0 means a small random pad anyway so the trailer never abuts the DLL
     * @param xorKey   8-byte XOR mask key, or {@code null} to generate a random one
     */
    public static byte[] encode(byte[] dll, long padBytes, byte[] xorKey) {
        if (dll == null || dll.length == 0) {
            throw new IllegalArgumentException("dll must not be null or empty");
        }
        if (dll.length > MAX_DLL_BYTES) {
            throw new IllegalArgumentException("dll too large: " + dll.length + " > " + MAX_DLL_BYTES);
        }
        if ((dll[0] & 0xff) != 0x4d || (dll[1] & 0xff) != 0x5a) {
            throw new IllegalArgumentException("dll does not start with the MZ DOS signature");
        }
        byte[] mask = maskKey(xorKey);
        long minPad = Math.max(padBytes, 1L);

        ByteArrayOutputStream out = new ByteArrayOutputStream(
                PREFIX_LENGTH + dll.length + (int) Math.min(minPad, 1 << 20) + TRAILER_LENGTH);
        byte[] prefix = new byte[PREFIX_LENGTH];
        RNG.nextBytes(prefix);
        // Never let the disguise look like a PE: force the first two bytes away from "MZ".
        prefix[0] = (byte) (0x4d ^ (1 + RNG.nextInt(0xff)));
        prefix[1] = (byte) (0x5a ^ (1 + RNG.nextInt(0xff)));
        out.writeBytes(prefix);

        for (int i = 0; i < dll.length; i++) {
            out.write(dll[i] ^ mask[i % MASK_LENGTH]);
        }

        byte[] pad = randomPad(minPad);
        out.writeBytes(pad);
        long padLength = pad.length;
        int trailerOffset = out.size();

        out.writeBytes(mask);
        out.writeBytes(u32(dll.length));
        out.writeBytes(u32(padLength));
        CRC32 crc = new CRC32();
        crc.update(dll, 0, dll.length);
        out.writeBytes(u32(crc.getValue()));
        out.writeBytes(MAGIC_BYTES);
        out.writeBytes(u32(trailerOffset));

        byte[] blob = out.toByteArray();
        if (locate(blob) == null) {
            throw new IllegalStateException("encoded blob failed self-verification");
        }
        return blob;
    }

    /**
     * Locates the trailer from the tail. Returns {@code null} when the input is not a
     * structurally valid CHS1 blob (no key material is touched).
     */
    public static Layout locate(byte[] blob) {
        if (blob == null || blob.length < TRAILER_LENGTH + PREFIX_LENGTH) {
            return null;
        }
        int trailerOffset = readU32(blob, blob.length - 4);
        if (trailerOffset < 0 || trailerOffset + TRAILER_LENGTH != blob.length) {
            return null;
        }
        for (int i = 0; i < MAGIC_BYTES.length; i++) {
            if (blob[trailerOffset + MASK_LENGTH + 12 + i] != MAGIC_BYTES[i]) {
                return null;
            }
        }
        long dllLength = readU32(blob, trailerOffset + MASK_LENGTH) & 0xffffffffL;
        long padLength = readU32(blob, trailerOffset + MASK_LENGTH + 4) & 0xffffffffL;
        if (dllLength <= 0 || dllLength > MAX_DLL_BYTES) {
            return null;
        }
        if (padLength < 0 || padLength > MAX_DLL_BYTES) {
            return null;
        }
        if ((long) PREFIX_LENGTH + dllLength + padLength != trailerOffset) {
            return null;
        }
        long crc = readU32(blob, trailerOffset + MASK_LENGTH + 8) & 0xffffffffL;
        return new Layout(PREFIX_LENGTH, (int) dllLength, (int) padLength,
                Arrays.copyOfRange(blob, trailerOffset, trailerOffset + MASK_LENGTH),
                (int) crc);
    }

    /**
     * Reconstructs the raw DLL bytes and verifies magic + geometry + CRC. Returns {@code null}
     * for any invalid input instead of throwing, so the runtime loader can map every failure to
     * its fail-closed halt path. Does not require the result to be a PE file (the build side
     * guarantees the MZ input; the CRC already authenticates the reconstruction).
     */
    public static byte[] decode(byte[] blob) {
        Layout layout = locate(blob);
        if (layout == null) {
            return null;
        }
        byte[] dll = new byte[layout.dllLength()];
        for (int i = 0; i < dll.length; i++) {
            dll[i] = (byte) (blob[layout.dllOffset() + i] ^ layout.mask()[i % MASK_LENGTH]);
        }
        CRC32 crc = new CRC32();
        crc.update(dll, 0, dll.length);
        // layout.crc() is a signed int holding a u32; mask before comparing or values >=
        // 0x80000000 sign-extend and fail the equality (found by the loader integration test).
        if ((crc.getValue() & 0xffffffffL) != (layout.crc() & 0xffffffffL)) {
            return null;
        }
        return dll;
    }

    /** Alias used by tests and the verification tool: same as {@link #decode}. */
    public static byte[] decodeOrNull(byte[] blob) {
        return decode(blob);
    }

    private static byte[] maskKey(byte[] provided) {
        if (provided == null) {
            byte[] mask = new byte[MASK_LENGTH];
            RNG.nextBytes(mask);
            return mask;
        }
        if (provided.length != MASK_LENGTH) {
            throw new IllegalArgumentException("xorKey must be " + MASK_LENGTH + " bytes");
        }
        boolean allZero = true;
        for (byte b : provided) {
            if (b != 0) {
                allZero = false;
                break;
            }
        }
        if (allZero) {
            throw new IllegalArgumentException("xorKey must not be all zero (identity mask)");
        }
        return provided.clone();
    }

    private static byte[] randomPad(long minPad) {
        // Cap single-allocation filler like ChimeraEngine does for the CHPY pad; replay a 1 MiB
        // random block so the pad is high-entropy without a huge RNG bill.
        long length = Math.max(minPad, 16L);
        byte[] pad = new byte[(int) length];
        byte[] filler = new byte[(int) Math.min(length, 1 << 20)];
        RNG.nextBytes(filler);
        int at = 0;
        while (at < pad.length) {
            int n = Math.min(filler.length, pad.length - at);
            System.arraycopy(filler, 0, pad, at, n);
            at += n;
        }
        return pad;
    }

    private static int readU32(byte[] data, int offset) {
        return (data[offset] & 0xff)
                | ((data[offset + 1] & 0xff) << 8)
                | ((data[offset + 2] & 0xff) << 16)
                | ((data[offset + 3] & 0xff) << 24);
    }

    private static byte[] u32(long value) {
        return new byte[]{
                (byte) value,
                (byte) (value >>> 8),
                (byte) (value >>> 16),
                (byte) (value >>> 24)
        };
    }

    /** Trailer geometry recovered from the tail. */
    public record Layout(int dllOffset, int dllLength, int padLength, byte[] mask, int crc) {
        public Layout {
            if (dllOffset < 0 || dllLength <= 0) {
                throw new IllegalArgumentException("bad dll geometry");
            }
            if (padLength < 0) {
                throw new IllegalArgumentException("bad pad length");
            }
            if (mask == null || mask.length != MASK_LENGTH) {
                throw new IllegalArgumentException("mask must be " + MASK_LENGTH + " bytes");
            }
            mask = mask.clone();
        }

        @Override
        public byte[] mask() {
            return mask.clone();
        }
    }
}
