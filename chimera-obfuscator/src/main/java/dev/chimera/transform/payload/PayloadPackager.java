package dev.chimera.transform.payload;

import dev.chimera.crypto.Crypto;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * S5 build side: appends one encrypted payload overlay to a native DLL.
 *
 * <p>On-disk layout (little-endian footer, exactly the format read by
 * {@code chimera_auth.cpp::s5_read_own_payload}):</p>
 * <pre>
 * [carrier DLL bytes][ciphertext(N)][nonce(12)][tag(16)]["CHPY"][u32 version=1][u64 N]
 *                    ^ overlay starts at carrierLength
 * </pre>
 *
 * <p>The footer is located from the tail only, so the carrier DLL never has to be parsed:
 * magic at {@code total - 44 + 28}, version at {@code total - 44 + 32}, payload length at
 * {@code total - 44 + 36}. The ciphertext therefore starts at
 * {@code total - 44 - N}.</p>
 *
 * <p>Key derivation follows the product ResourceKey chain with its own domain separator:</p>
 * <pre>
 * key = HKDF-SHA256(ikm = ResourceKey, salt = envSalt, info = "chimera/v1/payload", 32)
 * </pre>
 *
 * <p>Encryption is AES-256-GCM with a fresh 12-byte nonce, a 128-bit tag and no AAD (the native
 * extractor passes {@code nullptr} AAD; binding extra bytes here would break interop). A tampered
 * ciphertext/tag fails authentication in {@link #extract}; {@link #verify} is an unkeyed structural
 * check (it can only reject malformed overlays, never prove authenticity).</p>
 *
 * <p>{@code payload == null} means "self-extract": the carrier DLL itself is encrypted into the
 * overlay, so a loadable native image can later be materialized by the runtime loader. A non-null
 * payload is encrypted verbatim (for example a class payload). Empty payloads are rejected because
 * the native footer requires {@code payload_len > 0}.</p>
 */
public final class PayloadPackager {

    /** Overlay footer magic. Must match the native {@code "CHPY"} literal. */
    public static final String MAGIC = "CHPY";
    /** Overlay format version understood by the native reader. */
    public static final int VERSION = 1;
    public static final int NONCE_LENGTH = 12;
    public static final int TAG_LENGTH = 16;
    /** nonce(12) + tag(16) + magic(4) + version(4) + payloadLength(8). */
    public static final int FOOTER_LENGTH = NONCE_LENGTH + TAG_LENGTH + 4 + 4 + 8;
    /** Magic offset inside the footer. */
    public static final int FOOTER_MAGIC_OFFSET = NONCE_LENGTH + TAG_LENGTH;
    /** Version offset inside the footer. */
    public static final int FOOTER_VERSION_OFFSET = FOOTER_MAGIC_OFFSET + 4;
    /** Payload length offset inside the footer. */
    public static final int FOOTER_LENGTH_OFFSET = FOOTER_VERSION_OFFSET + 4;
    /** HKDF info/domain separator for the payload key. */
    public static final String KEY_DOMAIN = "chimera/v1/payload";
    public static final int KEY_LENGTH = 32;
    /** Hard cap for one overlay payload (also enforced by the runtime loader). */
    public static final int MAX_PAYLOAD_BYTES = 64 * 1024 * 1024;

    private static final byte[] MAGIC_BYTES = MAGIC.getBytes(StandardCharsets.US_ASCII);
    private static final int MAX_ENV_SALT_BYTES = 64;

    private PayloadPackager() {
    }

    /**
     * Appends an encrypted overlay to {@code dll}.
     *
     * @param dll         carrier bytes (usually a native DLL); never modified
     * @param payload     plaintext to hide, or {@code null} to encrypt {@code dll} itself
     * @param resourceKey 32-byte product ResourceKey
     * @param envSalt     HKDF salt (0..64 bytes; {@code null} is treated as empty)
     * @return a new array {@code dll || overlay}
     */
    public static byte[] appendTo(byte[] dll, byte[] payload, byte[] resourceKey, byte[] envSalt) {
        if (dll == null) {
            throw new IllegalArgumentException("dll must not be null");
        }
        byte[] plaintext = payload == null ? dll : payload;
        if (plaintext.length == 0) {
            throw new IllegalArgumentException("payload must not be empty");
        }
        if (plaintext.length > MAX_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("payload too large: " + plaintext.length
                    + " > " + MAX_PAYLOAD_BYTES);
        }

        byte[] key = deriveKey(resourceKey, envSalt);
        byte[] nonce = Crypto.random(NONCE_LENGTH);
        try {
            byte[] sealed = Crypto.aesGcmEncrypt(key, nonce, plaintext, null);
            int ciphertextLength = sealed.length - TAG_LENGTH;
            if (ciphertextLength <= 0) {
                throw new IllegalStateException("AES-GCM produced an empty ciphertext");
            }

            ByteArrayOutputStream out = new ByteArrayOutputStream(
                    dll.length + ciphertextLength + FOOTER_LENGTH);
            out.writeBytes(dll);
            out.write(sealed, 0, ciphertextLength);
            out.writeBytes(nonce);
            out.write(sealed, ciphertextLength, TAG_LENGTH);
            out.writeBytes(MAGIC_BYTES);
            out.writeBytes(intToLittleEndian(VERSION));
            out.writeBytes(longToLittleEndian(ciphertextLength));
            byte[] packaged = out.toByteArray();
            if (!verify(packaged) || packaged.length != dll.length + ciphertextLength + FOOTER_LENGTH) {
                throw new IllegalStateException("packaged overlay failed self-verification");
            }
            return packaged;
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    /**
     * Unkeyed structural validation: a well-formed tail, known magic/version and a payload length
     * that fits inside the array. Returns {@code false} for {@code null}, truncated or malformed
     * input. This does not authenticate the ciphertext (only {@link #extract} with the right key
     * can do that).
     */
    public static boolean verify(byte[] dllWithOverlay) {
        return locate(dllWithOverlay) != null;
    }

    /**
     * Locates the overlay from the tail. Returns {@code null} when the input is not a structurally
     * valid {@code CHPY} overlay. Never decrypts and never needs a key.
     */
    public static OverlayLayout locate(byte[] dllWithOverlay) {
        if (dllWithOverlay == null || dllWithOverlay.length < FOOTER_LENGTH) {
            return null;
        }
        final int footer = dllWithOverlay.length - FOOTER_LENGTH;
        for (int i = 0; i < MAGIC_BYTES.length; i++) {
            if (dllWithOverlay[footer + FOOTER_MAGIC_OFFSET + i] != MAGIC_BYTES[i]) {
                return null;
            }
        }
        int version = readIntLittleEndian(dllWithOverlay, footer + FOOTER_VERSION_OFFSET);
        if (version != VERSION) {
            return null;
        }
        long payloadLength = readLongLittleEndian(dllWithOverlay, footer + FOOTER_LENGTH_OFFSET);
        if (payloadLength <= 0 || payloadLength > MAX_PAYLOAD_BYTES) {
            return null;
        }
        long ciphertextOffset = footer - payloadLength;
        if (ciphertextOffset < 0) {
            return null;
        }
        byte[] nonce = Arrays.copyOfRange(dllWithOverlay, footer,
                footer + NONCE_LENGTH);
        byte[] tag = Arrays.copyOfRange(dllWithOverlay,
                footer + NONCE_LENGTH, footer + NONCE_LENGTH + TAG_LENGTH);
        return new OverlayLayout((int) ciphertextOffset, (int) payloadLength, nonce, tag);
    }

    /**
     * Decrypts the overlay. Build/test/verification API: the shipped runtime normally asks the
     * native DLL to extract the payload so the ResourceKey never enters Java.
     *
     * @throws IllegalArgumentException when the overlay is malformed, the key is invalid or the
     *                                  GCM tag does not authenticate (tampered ciphertext)
     */
    public static byte[] extract(byte[] dllWithOverlay, byte[] resourceKey, byte[] envSalt) {
        OverlayLayout layout = locate(dllWithOverlay);
        if (layout == null) {
            throw new IllegalArgumentException("no valid CHPY payload overlay");
        }
        byte[] key = deriveKey(resourceKey, envSalt);
        byte[] sealed = new byte[layout.ciphertextLength() + TAG_LENGTH];
        try {
            System.arraycopy(dllWithOverlay, layout.ciphertextOffset(), sealed, 0,
                    layout.ciphertextLength());
            byte[] tag = layout.tag();
            System.arraycopy(tag, 0, sealed, layout.ciphertextLength(), TAG_LENGTH);
            return Crypto.aesGcmDecrypt(key, layout.nonce(), sealed, null);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("payload authentication failed", e);
        } finally {
            Arrays.fill(key, (byte) 0);
            Arrays.fill(sealed, (byte) 0);
        }
    }

    /**
     * {@code HKDF-SHA256(ResourceKey, salt = envSalt, info = "chimera/v1/payload", 32)}.
     *
     * @param envSalt 0..64 bytes; {@code null} means an empty HKDF salt
     */
    public static byte[] deriveKey(byte[] resourceKey, byte[] envSalt) {
        if (resourceKey == null || resourceKey.length != KEY_LENGTH) {
            throw new IllegalArgumentException("resourceKey must be " + KEY_LENGTH + " bytes");
        }
        if (envSalt != null && envSalt.length > MAX_ENV_SALT_BYTES) {
            throw new IllegalArgumentException("envSalt must be 0.." + MAX_ENV_SALT_BYTES + " bytes");
        }
        return Crypto.hkdf(resourceKey, envSalt,
                KEY_DOMAIN.getBytes(StandardCharsets.UTF_8), KEY_LENGTH);
    }

    /** Overlay geometry recovered from the tail. */
    public record OverlayLayout(int carrierLength, int ciphertextLength, byte[] nonce, byte[] tag) {
        public OverlayLayout {
            if (carrierLength < 0) {
                throw new IllegalArgumentException("carrierLength must be >= 0");
            }
            if (ciphertextLength <= 0 || ciphertextLength > MAX_PAYLOAD_BYTES) {
                throw new IllegalArgumentException("bad ciphertext length: " + ciphertextLength);
            }
            if (nonce == null || nonce.length != NONCE_LENGTH) {
                throw new IllegalArgumentException("nonce must be " + NONCE_LENGTH + " bytes");
            }
            if (tag == null || tag.length != TAG_LENGTH) {
                throw new IllegalArgumentException("tag must be " + TAG_LENGTH + " bytes");
            }
            nonce = nonce.clone();
            tag = tag.clone();
        }

        /** Start of the ciphertext (== carrier length == end of the untouched DLL bytes). */
        public int ciphertextOffset() {
            return carrierLength;
        }

        /** Bytes occupied by the overlay: ciphertext + footer. */
        public int overlayLength() {
            return ciphertextLength + FOOTER_LENGTH;
        }

        /** Expected total array length for this overlay. */
        public int totalLength() {
            return carrierLength + overlayLength();
        }

        @Override
        public byte[] nonce() {
            return nonce.clone();
        }

        @Override
        public byte[] tag() {
            return tag.clone();
        }
    }

    private static int readIntLittleEndian(byte[] data, int offset) {
        return (data[offset] & 0xff)
                | ((data[offset + 1] & 0xff) << 8)
                | ((data[offset + 2] & 0xff) << 16)
                | ((data[offset + 3] & 0xff) << 24);
    }

    private static long readLongLittleEndian(byte[] data, int offset) {
        long value = 0L;
        for (int i = 0; i < 8; i++) {
            value |= (long) (data[offset + i] & 0xff) << (8 * i);
        }
        return value;
    }

    private static byte[] intToLittleEndian(int value) {
        return new byte[]{
                (byte) value,
                (byte) (value >>> 8),
                (byte) (value >>> 16),
                (byte) (value >>> 24)
        };
    }

    private static byte[] longToLittleEndian(long value) {
        byte[] out = new byte[8];
        for (int i = 0; i < 8; i++) {
            out[i] = (byte) (value >>> (8 * i));
        }
        return out;
    }
}
