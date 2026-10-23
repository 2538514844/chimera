package dev.chimera.attach;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.zip.CRC32;

/**
 * CHENC1: class-body container shared by the build (encrypt) and the attached agent (decrypt).
 *
 * <pre>
 * C H E N C 1 \0 | ver u8 | flags u8 | origLen u32 | crc32 u32 | nonce[12] | AES-GCM ciphertext
 * </pre>
 *
 * AAD is the class internal name, so a payload cannot be moved to another entry.
 */
public final class AgentCipher {

    public static final byte[] MAGIC = {'C', 'H', 'E', 'N', 'C', '1', 0};
    public static final int HEADER = MAGIC.length + 1 + 1 + 4 + 4 + 12;
    private static final int VERSION = 1;
    private static final int TAG_BITS = 128;
    private static final SecureRandom RANDOM = new SecureRandom();

    private AgentCipher() {
    }

    /** True when the bytes start with the CHENC1 magic (cheap, no crypto). */
    public static boolean isEncrypted(byte[] bytes) {
        if (bytes == null || bytes.length < HEADER + 16) {
            return false;
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (bytes[i] != MAGIC[i]) {
                return false;
            }
        }
        return true;
    }

    /** Encrypts one class body; {@code internalName} is bound as AAD. */
    public static byte[] encrypt(byte[] plain, byte[] key, String internalName) {
        try {
            byte[] nonce = new byte[12];
            RANDOM.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(internalName.getBytes(StandardCharsets.UTF_8));
            byte[] ct = cipher.doFinal(plain);
            CRC32 crc = new CRC32();
            crc.update(plain);
            ByteBuffer out = ByteBuffer.allocate(HEADER + ct.length);
            out.put(MAGIC);
            out.put((byte) VERSION);
            out.put((byte) 0);
            out.putInt(plain.length);
            out.putInt((int) crc.getValue());
            out.put(nonce);
            out.put(ct);
            return out.array();
        } catch (Exception e) {
            throw new IllegalStateException("class encryption failed for " + internalName, e);
        }
    }

    /** Decrypts one class body produced by {@link #encrypt(byte[], byte[], String)}. */
    public static byte[] decrypt(byte[] blob, byte[] key, String internalName) {
        try {
            ByteBuffer in = ByteBuffer.wrap(blob);
            byte[] magic = new byte[MAGIC.length];
            in.get(magic);
            int version = in.get() & 0xFF;
            in.get(); // flags
            int origLen = in.getInt();
            int expectedCrc = in.getInt();
            byte[] nonce = new byte[12];
            in.get(nonce);
            byte[] ct = new byte[in.remaining()];
            in.get(ct);
            if (version != VERSION) {
                throw new IllegalStateException("unsupported CHENC version " + version);
            }
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(internalName.getBytes(StandardCharsets.UTF_8));
            byte[] plain = cipher.doFinal(ct);
            if (plain.length != origLen) {
                throw new IllegalStateException("length mismatch");
            }
            CRC32 crc = new CRC32();
            crc.update(plain);
            if ((int) crc.getValue() != expectedCrc) {
                throw new IllegalStateException("crc mismatch");
            }
            return plain;
        } catch (Exception e) {
            throw new IllegalStateException("class decryption failed for " + internalName, e);
        }
    }
}
