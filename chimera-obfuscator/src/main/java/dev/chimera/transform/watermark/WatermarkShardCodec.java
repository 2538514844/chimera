package dev.chimera.transform.watermark;

import dev.chimera.crypto.Crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 3-of-5 threshold sharing + per-shard AES-GCM sealing for the watermark.
 *
 * <p>Each shard carries one evaluation of a degree-2 polynomial over GF(2^8) for every
 * byte of the watermark payload. Any three distinct shards reconstruct the payload;
 * fewer reveal nothing about it. On top of that, every shard is independently sealed
 * with AES-GCM under {@code HKDF(kek, envSalt, "chimera/v1/wm/shard/<index>")}, so a
 * flipped bit or a substituted shard is rejected by the GCM tag before it can pollute
 * reconstruction.</p>
 *
 * <p>The plaintext payload never appears on disk: only the fixed 9-byte shard header
 * (magic/version/index/total/threshold/flags), a random nonce length, a ciphertext
 * length and the GCM ciphertext are stored.</p>
 */
final class WatermarkShardCodec {

    static final int SHARD_COUNT = 5;
    static final int THRESHOLD = 3;

    static final int SHARD_MAGIC = 0x43485753; // "CHWS"
    static final int SHARD_VERSION = 1;
    static final int NONCE_LENGTH = 12;
    static final int TAG_LENGTH = 16;
    static final int MAX_SHARE_LENGTH = 16 * 1024 * 1024;

    private static final int[] EXP = new int[512];
    private static final int[] LOG = new int[256];

    static {
        // 3 is a primitive element of GF(2^8) modulo 0x11b; multiplying by 2 only walks a
        // subgroup (e.g. 3 would never get a logarithm), so the usual "x <<= 1" table is wrong here.
        int value = 1;
        for (int i = 0; i < 255; i++) {
            EXP[i] = value;
            LOG[value] = i;
            int next = value ^ (value << 1);
            if ((next & 0x100) != 0) {
                next ^= 0x11b;
            }
            value = next;
        }
        for (int i = 255; i < EXP.length; i++) {
            EXP[i] = EXP[i - 255];
        }
    }

    private WatermarkShardCodec() {
    }

    /** One recovered shard: its 1-based evaluation point plus the share bytes. */
    static final class Share {
        final int index;
        final byte[] data;

        Share(int index, byte[] data) {
            this.index = index;
            this.data = data;
        }

        int x() {
            return index + 1;
        }
    }

    /** Derives the AES key of one shard from the build KEK and environment salt. */
    static byte[] shardKey(byte[] kek, byte[] envSalt, int index) {
        return Crypto.hkdf(kek, envSalt,
                ("chimera/v1/wm/shard/" + index).getBytes(StandardCharsets.UTF_8), 32);
    }

    /**
     * Seals one share. The header is authenticated as AAD together with the shard index,
     * total, threshold and share length, which prevents cross-index substitution.
     */
    static byte[] seal(int index, byte[] share, byte[] itemKey) {
        if (share == null || itemKey == null) {
            throw new IllegalArgumentException("share and itemKey are required");
        }
        if (share.length > MAX_SHARE_LENGTH) {
            throw new IllegalArgumentException("share too large: " + share.length);
        }
        byte[] nonce = Crypto.random(NONCE_LENGTH);
        byte[] aad = aad(index, SHARD_COUNT, THRESHOLD, share.length);
        byte[] ciphertext = Crypto.aesGcmEncrypt(itemKey, nonce, share, aad);
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream(9 + 4 + NONCE_LENGTH + 4 + ciphertext.length);
            DataOutputStream out = new DataOutputStream(bos);
            out.writeInt(SHARD_MAGIC);
            out.writeByte(SHARD_VERSION);
            out.writeByte(index);
            out.writeByte(SHARD_COUNT);
            out.writeByte(THRESHOLD);
            out.writeByte(0); // flags
            out.writeInt(share.length);
            out.write(nonce);
            out.writeInt(ciphertext.length);
            out.write(ciphertext);
            out.flush();
            return bos.toByteArray();
        } catch (IOException ex) {
            throw new IllegalStateException("cannot encode watermark shard", ex);
        }
    }

    /**
     * Opens one shard. Returns {@code null} for anything that is missing, truncated,
     * mis-indexed, from another build, or bit-flipped; callers treat that shard as erased.
     */
    static byte[] open(byte[] file, int expectedIndex, byte[] itemKey) {
        if (file == null || itemKey == null || expectedIndex < 0 || expectedIndex >= SHARD_COUNT) {
            return null;
        }
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(file))) {
            int magic = in.readInt();
            int version = in.readUnsignedByte();
            int index = in.readUnsignedByte();
            int total = in.readUnsignedByte();
            int threshold = in.readUnsignedByte();
            int flags = in.readUnsignedByte();
            int shareLength = in.readInt();
            if (magic != SHARD_MAGIC || version != SHARD_VERSION || index != expectedIndex
                    || total != SHARD_COUNT || threshold != THRESHOLD || flags != 0
                    || shareLength < 0 || shareLength > MAX_SHARE_LENGTH) {
                return null;
            }
            byte[] nonce = new byte[NONCE_LENGTH];
            in.readFully(nonce);
            int ciphertextLength = in.readInt();
            if (ciphertextLength != shareLength + TAG_LENGTH || in.available() != ciphertextLength) {
                return null;
            }
            byte[] ciphertext = new byte[ciphertextLength];
            in.readFully(ciphertext);
            byte[] plain = Crypto.aesGcmDecrypt(itemKey, nonce, ciphertext,
                    aad(index, total, threshold, shareLength));
            return plain.length == shareLength ? plain : null;
        } catch (IOException | RuntimeException ex) {
            return null;
        }
    }

    private static byte[] aad(int index, int total, int threshold, int shareLength) {
        return ("chimera/wm/shard/" + index + "/" + total + "/" + threshold + "/" + shareLength)
                .getBytes(StandardCharsets.UTF_8);
    }

    /** Splits the payload into {@link #SHARD_COUNT} polynomial shares. */
    static byte[][] split(byte[] secret) {
        if (secret == null || secret.length > MAX_SHARE_LENGTH) {
            throw new IllegalArgumentException("invalid watermark payload length");
        }
        byte[] coefficients = Crypto.random(secret.length * 2);
        byte[][] shares = new byte[SHARD_COUNT][secret.length];
        for (int p = 0; p < secret.length; p++) {
            int value = secret[p] & 0xff;
            int a1 = coefficients[p] & 0xff;
            int a2 = coefficients[secret.length + p] & 0xff;
            for (int i = 0; i < SHARD_COUNT; i++) {
                int x = i + 1;
                int y = value ^ mul(a1, x) ^ mul(a2, mul(x, x));
                shares[i][p] = (byte) y;
            }
        }
        return shares;
    }

    /** Lagrange interpolation at x=0 over GF(2^8) for exactly {@link #THRESHOLD} shares. */
    static byte[] combine(List<Share> shares, int length) {
        if (shares == null || shares.size() != THRESHOLD) {
            throw new IllegalArgumentException("exactly " + THRESHOLD + " shares are required");
        }
        if (length < 0 || length > MAX_SHARE_LENGTH) {
            throw new IllegalArgumentException("invalid share length: " + length);
        }
        int[] x = new int[THRESHOLD];
        int[] lambda = new int[THRESHOLD];
        for (int i = 0; i < THRESHOLD; i++) {
            Share share = shares.get(i);
            if (share == null || share.data == null || share.data.length != length) {
                throw new IllegalArgumentException("share length mismatch");
            }
            x[i] = share.x();
        }
        for (int j = 0; j < THRESHOLD; j++) {
            int numerator = 1;
            int denominator = 1;
            for (int m = 0; m < THRESHOLD; m++) {
                if (m == j) {
                    continue;
                }
                // Characteristic 2: (0 - x_m) == x_m and (x_j - x_m) == x_j ^ x_m.
                numerator = mul(numerator, x[m]);
                denominator = mul(denominator, x[j] ^ x[m]);
            }
            lambda[j] = div(numerator, denominator);
        }
        byte[] out = new byte[length];
        for (int p = 0; p < length; p++) {
            int value = 0;
            for (int j = 0; j < THRESHOLD; j++) {
                value ^= mul(shares.get(j).data[p] & 0xff, lambda[j]);
            }
            out[p] = (byte) value;
        }
        return out;
    }

    /** All {@code k}-subsets of {@code 0..n-1}, used for majority voting over shards. */
    static List<int[]> combinations(int n, int k) {
        List<int[]> result = new ArrayList<>();
        if (n < k || k <= 0) {
            return result;
        }
        int[] current = new int[k];
        collectCombinations(0, 0, n, k, current, result);
        return result;
    }

    private static void collectCombinations(int start, int depth, int n, int k,
                                            int[] current, List<int[]> result) {
        if (depth == k) {
            result.add(current.clone());
            return;
        }
        int remaining = k - depth;
        for (int i = start; i <= n - remaining; i++) {
            current[depth] = i;
            collectCombinations(i + 1, depth + 1, n, k, current, result);
        }
    }

    static int mul(int a, int b) {
        if (a == 0 || b == 0) {
            return 0;
        }
        return EXP[LOG[a] + LOG[b]];
    }

    static int div(int a, int b) {
        if (b == 0) {
            throw new ArithmeticException("division by zero in GF(256)");
        }
        if (a == 0) {
            return 0;
        }
        int exponent = LOG[a] - LOG[b];
        if (exponent < 0) {
            exponent += 255;
        }
        return EXP[exponent];
    }

    static void wipe(byte[] data) {
        if (data != null) {
            Arrays.fill(data, (byte) 0);
        }
    }
}
