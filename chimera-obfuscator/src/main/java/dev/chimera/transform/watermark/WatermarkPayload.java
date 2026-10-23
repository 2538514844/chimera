package dev.chimera.transform.watermark;

import dev.chimera.crypto.Crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Binary watermark payload (plaintext inside the threshold shares).
 *
 * <pre>
 * int    magic       0x43485731 ("CHW1")
 * int    version     1
 * short  buildIdLen  UTF-8
 * bytes  buildId
 * short  tagLen      HMAC(licenseId, salt)
 * bytes  licenseTag
 * int    variantCount
 *   short nameLen, bytes internalName, byte k, k bytes (0/1)
 * int    structureCount
 *   short nameLen, bytes internalName, byte orderBit (0/1)
 * bytes  sha256(core)[32]
 * </pre>
 *
 * <p>The trailing digest lets the extractor reject a bad reconstruction before it parses
 * attacker-controlled lengths. It is an integrity check for the sharing layer, not a
 * replacement for the AES-GCM tag on every shard.</p>
 */
final class WatermarkPayload {

    static final int MAGIC = 0x43485731; // "CHW1"
    static final int VERSION = 1;
    static final int CHECKSUM_LENGTH = 32;
    static final int MAX_PAYLOAD = 16 * 1024 * 1024;
    static final int MAX_CLASSES = 200_000;
    static final int MAX_NAME_BYTES = 1024;
    static final int MAX_BUILD_ID_BYTES = 4096;
    static final int MAX_LICENSE_TAG_BYTES = 1024;
    static final int MAX_VARIANT_BITS = 32;

    private WatermarkPayload() {
    }

    static final class Decoded {
        final String buildId;
        final byte[] licenseTag;
        final Map<String, int[]> variantBits;
        final Map<String, Integer> structureOrderBits;

        Decoded(String buildId, byte[] licenseTag,
                Map<String, int[]> variantBits, Map<String, Integer> structureOrderBits) {
            this.buildId = buildId;
            this.licenseTag = licenseTag;
            this.variantBits = variantBits;
            this.structureOrderBits = structureOrderBits;
        }
    }

    static byte[] encode(String buildId, byte[] licenseTag,
                         Map<String, int[]> variantBits,
                         Map<String, Integer> structureOrderBits) {
        if (buildId == null || buildId.isEmpty()) {
            throw new IllegalArgumentException("buildId is required");
        }
        if (licenseTag == null || licenseTag.length == 0 || licenseTag.length > MAX_LICENSE_TAG_BYTES) {
            throw new IllegalArgumentException("licenseTag must be 1.." + MAX_LICENSE_TAG_BYTES + " bytes");
        }
        byte[] buildIdBytes = buildId.getBytes(StandardCharsets.UTF_8);
        if (buildIdBytes.length > MAX_BUILD_ID_BYTES) {
            throw new IllegalArgumentException("buildId too long");
        }
        Map<String, int[]> variants = variantBits == null ? Collections.emptyMap() : variantBits;
        Map<String, Integer> structures = structureOrderBits == null
                ? Collections.emptyMap() : structureOrderBits;
        if (variants.size() > MAX_CLASSES || structures.size() > MAX_CLASSES) {
            throw new IllegalArgumentException("too many watermark classes");
        }
        try {
            ByteArrayOutputStream coreBytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(coreBytes);
            out.writeInt(MAGIC);
            out.writeInt(VERSION);
            out.writeShort(buildIdBytes.length);
            out.write(buildIdBytes);
            out.writeShort(licenseTag.length);
            out.write(licenseTag);
            out.writeInt(variants.size());
            for (Map.Entry<String, int[]> entry : variants.entrySet()) {
                String name = requireName(entry.getKey());
                int[] bits = entry.getValue();
                if (bits == null || bits.length > MAX_VARIANT_BITS) {
                    throw new IllegalArgumentException("invalid variant bit count for " + name);
                }
                byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
                out.writeShort(nameBytes.length);
                out.write(nameBytes);
                out.writeByte(bits.length);
                for (int bit : bits) {
                    if (bit != 0 && bit != 1) {
                        throw new IllegalArgumentException("variant bit must be 0/1: " + bit);
                    }
                    out.writeByte(bit);
                }
            }
            out.writeInt(structures.size());
            for (Map.Entry<String, Integer> entry : structures.entrySet()) {
                String name = requireName(entry.getKey());
                Integer bit = entry.getValue();
                if (bit == null || (bit != 0 && bit != 1)) {
                    throw new IllegalArgumentException("structure order bit must be 0/1");
                }
                byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
                out.writeShort(nameBytes.length);
                out.write(nameBytes);
                out.writeByte(bit);
            }
            out.flush();
            byte[] core = coreBytes.toByteArray();
            if (core.length + CHECKSUM_LENGTH > MAX_PAYLOAD) {
                throw new IllegalArgumentException("watermark payload too large: " + core.length);
            }
            byte[] checksum = Crypto.sha256(core);
            byte[] payload = new byte[core.length + CHECKSUM_LENGTH];
            System.arraycopy(core, 0, payload, 0, core.length);
            System.arraycopy(checksum, 0, payload, core.length, CHECKSUM_LENGTH);
            return payload;
        } catch (IOException ex) {
            throw new IllegalStateException("cannot encode watermark payload", ex);
        }
    }

    /** Parses and integrity-checks a reconstructed payload; null means reject. */
    static Decoded decode(byte[] payload) {
        if (payload == null || payload.length < CHECKSUM_LENGTH + 16
                || payload.length > MAX_PAYLOAD) {
            return null;
        }
        int coreLength = payload.length - CHECKSUM_LENGTH;
        byte[] core = Arrays.copyOf(payload, coreLength);
        byte[] expected = Arrays.copyOfRange(payload, coreLength, payload.length);
        if (!MessageDigest.isEqual(Crypto.sha256(core), expected)) {
            Arrays.fill(core, (byte) 0);
            return null;
        }
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(core))) {
            int magic = in.readInt();
            int version = in.readInt();
            if (magic != MAGIC || version != VERSION) {
                return null;
            }
            String buildId = readString(in, MAX_BUILD_ID_BYTES, false);
            byte[] licenseTag = readBytes(in, MAX_LICENSE_TAG_BYTES, true);
            int variantCount = in.readInt();
            if (variantCount < 0 || variantCount > MAX_CLASSES) {
                return null;
            }
            Map<String, int[]> variants = new LinkedHashMap<>();
            for (int i = 0; i < variantCount; i++) {
                String name = readString(in, MAX_NAME_BYTES, false);
                int bitCount = in.readUnsignedByte();
                if (bitCount > MAX_VARIANT_BITS) {
                    return null;
                }
                int[] bits = new int[bitCount];
                for (int b = 0; b < bitCount; b++) {
                    int bit = in.readUnsignedByte();
                    if (bit != 0 && bit != 1) {
                        return null;
                    }
                    bits[b] = bit;
                }
                if (variants.put(name, bits) != null) {
                    return null;
                }
            }
            int structureCount = in.readInt();
            if (structureCount < 0 || structureCount > MAX_CLASSES) {
                return null;
            }
            Map<String, Integer> structures = new LinkedHashMap<>();
            for (int i = 0; i < structureCount; i++) {
                String name = readString(in, MAX_NAME_BYTES, false);
                int bit = in.readUnsignedByte();
                if (bit != 0 && bit != 1) {
                    return null;
                }
                if (structures.put(name, bit) != null) {
                    return null;
                }
            }
            if (in.available() != 0) {
                return null;
            }
            return new Decoded(buildId, licenseTag,
                    Collections.unmodifiableMap(variants),
                    Collections.unmodifiableMap(structures));
        } catch (IOException | RuntimeException ex) {
            return null;
        } finally {
            Arrays.fill(core, (byte) 0);
        }
    }

    private static String readString(DataInputStream in, int maxBytes, boolean allowEmpty)
            throws IOException {
        int length = in.readUnsignedShort();
        if (length > maxBytes || (!allowEmpty && length == 0)) {
            throw new IOException("bad string length");
        }
        byte[] bytes = new byte[length];
        in.readFully(bytes);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static byte[] readBytes(DataInputStream in, int maxBytes, boolean requireNonEmpty)
            throws IOException {
        int length = in.readUnsignedShort();
        if (length > maxBytes || (requireNonEmpty && length == 0)) {
            throw new IOException("bad byte length");
        }
        byte[] bytes = new byte[length];
        in.readFully(bytes);
        return bytes;
    }

    private static String requireName(String name) {
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("watermark class name is required");
        }
        int bytes = name.getBytes(StandardCharsets.UTF_8).length;
        if (bytes > MAX_NAME_BYTES) {
            throw new IllegalArgumentException("watermark class name too long");
        }
        return name;
    }
}
