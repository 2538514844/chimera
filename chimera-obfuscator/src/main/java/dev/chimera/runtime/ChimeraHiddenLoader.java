package dev.chimera.runtime;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.lang.invoke.MethodHandles;
import java.util.Arrays;

/**
 * S5 runtime side: opens one encrypted class payload (built by
 * {@code dev.chimera.transform.encrypt.ClassPayloadBuilder}) and defines the class as a hidden
 * class of this loader's nest.
 *
 * <p>Decryption never receives a key in Java: each chunk is opened through the package-private
 * {@link ChimeraRuntime#decryptItemBridge(String, int, byte[], byte[], byte[])} bridge, which is
 * the existing op9 DECRYPT_DATA path in authorized sessions (ResourceKey lives only in the native
 * handle) and the legacy HKDF+AES-GCM path in dev/no-handle builds.</p>
 *
 * <p>Fail-closed contract: every failure (bad payload geometry, wrong key, tampered bytes,
 * {@code defineHiddenClass} rejection) marks the runtime poisoned, wipes the plaintext buffers and
 * returns {@code null}. No catchable authorization exception escapes. Decrypted class bytes are
 * zeroized after {@code defineHiddenClass} copied them into the JVM (the JVM keeps its own internal
 * copy; this only closes the application-level plaintext window, same limitation as M3/B6).</p>
 */
public final class ChimeraHiddenLoader {

    /** "CHCP" - must match {@code ClassPayloadBuilder.MAGIC}. */
    public static final int MAGIC = 0x43484350;
    /** Must match {@code ClassPayloadBuilder.VERSION}. */
    public static final int VERSION = 1;
    /** op9 kind; must match {@code ClassPayloadBuilder.KIND}. */
    public static final String KIND = "class";
    public static final int NONCE_LENGTH = 12;
    public static final int TAG_LENGTH = 16;
    public static final int MIN_CHUNK_SIZE = 256;
    public static final int MAX_CHUNK_SIZE = 48 * 1024;
    public static final int MAX_TOTAL_BYTES = 16 * 1024 * 1024;

    private static volatile long wipeCount;
    private static volatile boolean lastPlaintextWiped;
    private static volatile boolean poisoned;
    private static volatile String lastFailureReason;

    private ChimeraHiddenLoader() {
    }

    /**
     * Opens {@code payload}, defines the hidden class and returns it. Returns {@code null} when any
     * validation/decryption/definition step fails (runtime is poisoned in that case).
     */
    public static Class<?> load(byte[] payload) {
        return load(payload, null);
    }

    /**
     * Same as {@link #load(byte[])} but additionally verifies the SHA-256 of the decrypted class
     * bytes before defining them (constant-time comparison). A {@code null} digest disables the
     * check.
     */
    public static Class<?> load(byte[] payload, byte[] expectedClassSha256) {
        byte[] plaintext = null;
        try {
            if (payload == null || payload.length < 6 * 4 + NONCE_LENGTH + TAG_LENGTH) {
                return fail("payload too short");
            }
            DataInputStream in = new DataInputStream(new ByteArrayInputStream(payload));
            int magic = in.readInt();
            int version = in.readInt();
            int payloadId = in.readInt();
            int chunkSize = in.readInt();
            int totalLength = in.readInt();
            int chunkCount = in.readInt();
            if (magic != MAGIC || version != VERSION) return fail("bad payload header");
            if (payloadId < 0) return fail("bad payload id");
            if (chunkSize < MIN_CHUNK_SIZE || chunkSize > MAX_CHUNK_SIZE) {
                return fail("bad chunk size");
            }
            if (totalLength <= 0 || totalLength > MAX_TOTAL_BYTES) return fail("bad total length");
            int expectedChunkCount = (totalLength + chunkSize - 1) / chunkSize;
            if (chunkCount != expectedChunkCount) return fail("bad chunk count");

            plaintext = new byte[totalLength];
            for (int index = 0; index < chunkCount; index++) {
                byte[] nonce = new byte[NONCE_LENGTH];
                in.readFully(nonce);
                int ciphertextLength = in.readInt();
                int expectedPlain = Math.min(chunkSize, totalLength - index * chunkSize);
                if (ciphertextLength != expectedPlain + TAG_LENGTH) {
                    return fail("bad chunk ciphertext length");
                }
                byte[] ciphertext = new byte[ciphertextLength];
                in.readFully(ciphertext);
                byte[] chunk = ChimeraRuntime.decryptItemBridge(KIND, payloadId, nonce, ciphertext,
                        chunkAad(payloadId, index, totalLength, chunkCount));
                if (chunk == null || chunk.length != expectedPlain) {
                    if (chunk != null) Arrays.fill(chunk, (byte) 0);
                    return fail("chunk decrypt failed");
                }
                System.arraycopy(chunk, 0, plaintext, index * chunkSize, chunk.length);
                Arrays.fill(chunk, (byte) 0);
            }
            if (in.available() != 0) return fail("trailing payload bytes");

            if (expectedClassSha256 != null) {
                if (expectedClassSha256.length != 32) return fail("bad class digest length");
                byte[] actual = sha256(plaintext);
                boolean matches = constantTimeEquals(actual, expectedClassSha256);
                Arrays.fill(actual, (byte) 0);
                if (!matches) return fail("class digest mismatch");
            }

            MethodHandles.Lookup lookup = MethodHandles.lookup();
            Class<?> hidden = lookup.defineHiddenClass(plaintext, true,
                    MethodHandles.Lookup.ClassOption.NESTMATE).lookupClass();
            if (hidden == null || !hidden.isHidden()) return fail("hidden class definition failed");
            return hidden;
        } catch (Throwable t) {
            if (DebugSwitches.property("chimera.s5.debug") != null) {
                t.printStackTrace();
            }
            return fail("load failed: " + t.getClass().getSimpleName()
                    + (t.getMessage() == null ? "" : ": " + t.getMessage()));
        } finally {
            if (plaintext != null) {
                Arrays.fill(plaintext, (byte) 0);
                lastPlaintextWiped = isAllZero(plaintext);
                wipeCount++;
            }
        }
    }

    /** True once a load failed; the runtime was poisoned through the existing bridge as well. */
    public static boolean isPoisoned() {
        return poisoned;
    }

    /** Number of decrypted class-byte buffers wiped so far (diagnostics/tests). */
    public static long wipeCount() {
        return wipeCount;
    }

    /** Whether the most recent decrypted buffer was observed all-zero after the wipe. */
    public static boolean lastPlaintextWiped() {
        return lastPlaintextWiped;
    }

    /** Last fail-closed reason for diagnostics (contains no key/plaintext material). */
    public static String lastFailureReason() {
        return lastFailureReason;
    }

    /** Test hook: clears only this loader's poison flag (the runtime key can reset its own state). */
    public static void resetPoisonForTests() {
        poisoned = false;
        lastPlaintextWiped = false;
        wipeCount = 0L;
        lastFailureReason = null;
    }

    /** AAD bound to the payload/chunk; mirrors ClassPayloadBuilder.chunkAad and native op9. */
    public static byte[] chunkAad(int payloadId, int index, int totalLength, int chunkCount) {
        return ("chimera/s5/class/" + payloadId + "/" + index + "/" + totalLength + "/" + chunkCount)
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    private static Class<?> fail(String reason) {
        lastFailureReason = reason;
        poisoned = true;
        try {
            ChimeraRuntime.markPoisonBridge();
        } catch (Throwable ignored) {
            // poisoning is best effort; the null return still fails closed
        }
        if (DebugSwitches.property("chimera.s5.debug") != null) {
            System.err.println("[chimera-hidden] " + reason);
        }
        return null;
    }

    private static byte[] sha256(byte[] data) throws Exception {
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) return false;
        int difference = 0;
        for (int i = 0; i < a.length; i++) {
            difference |= a[i] ^ b[i];
        }
        return difference == 0;
    }

    private static boolean isAllZero(byte[] data) {
        for (byte value : data) {
            if (value != 0) return false;
        }
        return true;
    }
}
