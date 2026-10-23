package dev.chimera.runtime;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;

/**
 * S5 runtime side: materializes the native payload hidden in the DLL's {@code CHPY} overlay into
 * a staged file that the native bootstrapper can consume from its tail.
 *
 * <p>The overlay is never decrypted in Java when the native entry points exist. The loader probes
 * {@code ChimeraRuntime} reflectively for the existing JNI surface:</p>
 * <pre>
 * int    nativePayloadAvailable()
 * long   nativePayloadSize()
 * byte[] nativePayloadDigest()
 * byte[] nativePayloadExtract(long handle, int offset, int length)   // preferred
 *        (a 1-arg long or 0-arg variant is also accepted)
 * </pre>
 *
 * <p>Fail-closed contract: if any entry point is missing, the overlay is unavailable, the size or
 * digest is invalid, extraction fails, the extracted length does not match, or the temp file cannot
 * be written, this class returns {@code null}, sets its poison flag and best-effort poisons the
 * runtime through {@code markPoisonBridge()} (when that method is present). No authorization
 * exception escapes: every failure is caught as {@link Throwable}, partial temp files are deleted
 * in the failure path and plaintext buffers are wiped in {@code finally}.</p>
 *
 * <p>The successful path stages the extracted bytes through {@link PayloadTempFile}: a real ZIP
 * decoy named {@code lib<random>.zip} whose trailing bytes are the payload. Before returning the
 * absolute path the loader verifies that the file starts with the ZIP local header
 * ({@code PK\x03\x04}), is at least as long as the payload, and that its tail still equals the
 * extracted plaintext. Callers recover the payload from that tail (the path is a disguise, not a
 * loadable native image) and must call {@link #release(String)} immediately (typically in a
 * {@code finally} block); on Windows a mapped file may not be deletable while in use, in which
 * case release schedules the file for deletion at JVM exit instead of leaking it silently.</p>
 *
 * <p>This class deliberately uses reflection for the native surface so it remains a single,
 * dependency-free runtime file and so a build without the JNI methods fails closed instead of
 * failing to link.</p>
 */
public final class ChimeraPayloadLoader {

    /** Mirrors {@code PayloadPackager.MAX_PAYLOAD_BYTES}. */
    public static final long MAX_PAYLOAD_BYTES = 64L * 1024 * 1024L;
    public static final int DIGEST_LENGTH = 32;

    private static final String RUNTIME_CLASS = "dev.chimera.runtime.ChimeraRuntime";
    /** Prefix-check buffer for the staged tail comparison. */
    private static final int TAIL_COMPARE_CHUNK = 8192;

    private static volatile boolean poisoned;
    private static volatile String lastFailureReason;
    private static volatile byte[] lastNativeDigest;
    private static volatile long lastExtractedSize;
    private static volatile String lastTempPath;

    private ChimeraPayloadLoader() {
    }

    /**
     * The native overlay surface. Implementations may throw; every throwable is treated as a
     * fail-closed failure by {@link #loadNativePayload(long, NativeProbe, Path)}.
     */
    public interface NativeProbe {
        /** Native {@code nativePayloadAvailable() == 1}. */
        boolean available();

        /** Ciphertext size in bytes; must be in {@code 1..MAX_PAYLOAD_BYTES}. */
        long size();

        /** SHA-256 fingerprint of the ciphertext (native {@code nativePayloadDigest()}). */
        byte[] digest();

        /** Decrypted payload slice; must return exactly {@code length} bytes for the requested range. */
        byte[] extract(long sessionHandle, int offset, int length);
    }

    /**
     * Production entry point: resolves the current native session handle and the reflective native
     * probe, then materializes the payload. Returns {@code null} (fail-closed) when the native
     * surface or the overlay is unavailable.
     */
    public static String loadNativePayload() {
        return loadNativePayload(resolveSessionHandle(), reflectiveProbe(), defaultTempDirectory());
    }

    /** Same as {@link #loadNativePayload()} with an explicit session handle. */
    public static String loadNativePayload(long sessionHandle) {
        return loadNativePayload(sessionHandle, reflectiveProbe(), defaultTempDirectory());
    }

    /**
     * Materializes the native payload into {@code tempDirectory}.
     *
     * <p>Returns the absolute temp-file path, or {@code null} on any failure. The returned file is
     * a ZIP-disguised staging file (see {@link PayloadTempFile}), not a loadable image; the caller
     * must consume the payload tail and then call {@link #release(String)}.</p>
     *
     * @param sessionHandle native SessionHandle (may be {@code 0} when the extractor has no handle
     *                      parameter)
     * @param probe         native surface, or {@code null} to fail closed
     * @param tempDirectory existing directory for the file; {@code null} uses the system temp dir
     */
    public static String loadNativePayload(long sessionHandle, NativeProbe probe, Path tempDirectory) {
        byte[] plaintext = null;
        Path temp = null;
        try {
            if (probe == null) {
                return fail("native payload API absent (fail-closed)");
            }
            if (!probe.available()) {
                return fail("native payload overlay unavailable");
            }
            long size = probe.size();
            if (size <= 0L || size > MAX_PAYLOAD_BYTES) {
                return fail("native payload size out of range: " + size);
            }
            byte[] digest = probe.digest();
            if (digest == null || digest.length != DIGEST_LENGTH) {
                return fail("native payload digest unavailable");
            }
            lastNativeDigest = digest.clone();

            Path directory = tempDirectory != null ? tempDirectory : defaultTempDirectory();
            if (directory == null || !Files.isDirectory(directory)) {
                return fail("payload temp directory unavailable");
            }

            int length = (int) size;
            plaintext = probe.extract(sessionHandle, 0, length);
            if (plaintext == null || plaintext.length != length) {
                return fail("native payload extract length mismatch");
            }

            temp = PayloadTempFile.write(plaintext, directory);
            String problem = stagedPayloadProblem(temp, plaintext);
            if (problem != null) {
                PayloadTempFile.deleteQuietly(temp);
                return fail("payload staging file " + problem + " (fail-closed)");
            }

            lastExtractedSize = length;
            lastTempPath = temp.toAbsolutePath().toString();
            return lastTempPath;
        } catch (Throwable t) {
            if (temp != null) {
                PayloadTempFile.deleteQuietly(temp);
            }
            return fail("payload load failed: " + t.getClass().getSimpleName()
                    + (t.getMessage() == null ? "" : ": " + t.getMessage()));
        } finally {
            if (plaintext != null) {
                Arrays.fill(plaintext, (byte) 0);
            }
        }
    }

    /**
     * Deletes the materialized payload. Idempotent and never throws. Returns {@code true} when the
     * file no longer exists afterwards; when deletion is impossible (loaded DLL on Windows) the
     * file is scheduled for deletion at JVM exit and {@code false} is returned.
     */
    public static boolean release(String path) {
        if (path == null || path.isEmpty()) {
            return true;
        }
        Path temp;
        try {
            temp = Paths.get(path);
        } catch (Throwable t) {
            return false;
        }
        return PayloadTempFile.deleteQuietly(temp);
    }

    /** True after any fail-closed outcome; never cleared except by {@link #resetPoisonForTests()}. */
    public static boolean isPoisoned() {
        return poisoned;
    }

    /** Last failure reason for diagnostics; contains no key or plaintext material. */
    public static String lastFailureReason() {
        return lastFailureReason;
    }

    /** SHA-256 of the ciphertext reported by the native overlay (diagnostics only). */
    public static byte[] lastNativeDigest() {
        byte[] digest = lastNativeDigest;
        return digest == null ? null : digest.clone();
    }

    /** Plaintext size of the last successful extraction. */
    public static long lastExtractedSize() {
        return lastExtractedSize;
    }

    /** Temp path of the last successful extraction (diagnostics only). */
    public static String lastTempPath() {
        return lastTempPath;
    }

    /**
     * Reflective probe over {@code ChimeraRuntime}'s existing JNI methods. Returns {@code null} when
     * the class or any required method is missing (fail-closed).
     */
    public static NativeProbe reflectiveProbe() {
        try {
            Class<?> runtime = Class.forName(RUNTIME_CLASS);
            Method available = findZeroArgStatic(runtime, "nativePayloadAvailable");
            Method size = findZeroArgStatic(runtime, "nativePayloadSize");
            Method digest = findZeroArgStatic(runtime, "nativePayloadDigest");
            Method extract = findExtract(runtime);
            if (available == null || size == null || digest == null || extract == null) {
                return null;
            }
            return new ReflectiveProbe(available, size, digest, extract);
        } catch (Throwable t) {
            return null;
        }
    }

    /**
     * Resolves the current native SessionHandle for the extractor. Looks for a zero-arg static
     * {@code sessionHandle()/getSessionHandle()/...} accessor and otherwise reads the existing
     * private {@code nativeSessionHandle} field. Returns {@code 0} when none is available.
     */
    public static long resolveSessionHandle() {
        try {
            Class<?> runtime = Class.forName(RUNTIME_CLASS);
            for (String name : new String[]{"sessionHandle", "getSessionHandle",
                    "activeSessionHandle", "currentSessionHandle"}) {
                Method method = findZeroArgStatic(runtime, name);
                if (method == null) {
                    continue;
                }
                Object value = invoke(method);
                if (value instanceof Number) {
                    return ((Number) value).longValue();
                }
            }
            for (Field field : runtime.getDeclaredFields()) {
                if ("nativeSessionHandle".equals(field.getName())
                        && Modifier.isStatic(field.getModifiers())
                        && field.getType() == long.class) {
                    try {
                        field.setAccessible(true);
                        return field.getLong(null);
                    } catch (Throwable ignored) {
                        return 0L;
                    }
                }
            }
        } catch (Throwable ignored) {
            // no runtime class: no handle
        }
        return 0L;
    }

    /** Test hook: clears only this loader's poison/diagnostic state. */
    public static void resetPoisonForTests() {
        poisoned = false;
        lastFailureReason = null;
        lastNativeDigest = null;
        lastExtractedSize = 0L;
        lastTempPath = null;
    }

    // ------------------------------------------------------------------ internals

    private static String fail(String reason) {
        lastFailureReason = reason;
        poisoned = true;
        poisonRuntimeBridge();
        return null;
    }

    private static void poisonRuntimeBridge() {
        try {
            Class<?> runtime = Class.forName(RUNTIME_CLASS);
            Method bridge = null;
            for (Method method : runtime.getDeclaredMethods()) {
                if ("markPoisonBridge".equals(method.getName())
                        && method.getParameterCount() == 0
                        && Modifier.isStatic(method.getModifiers())) {
                    bridge = method;
                    break;
                }
            }
            if (bridge != null) {
                bridge.setAccessible(true);
                bridge.invoke(null);
            }
        } catch (Throwable ignored) {
            // poisoning is best effort; the null return still fails closed
        }
    }

    /**
     * Post-write verification: ZIP local header, minimum length and exact payload tail. Returns
     * {@code null} when the staged file is usable, otherwise a diagnostic fragment that contains no
     * plaintext.
     */
    private static String stagedPayloadProblem(Path file, byte[] payload) {
        try {
            if (!Files.isRegularFile(file)) {
                return "is not a regular file";
            }
            long size = Files.size(file);
            if (size < payload.length) {
                return "is shorter than the payload (length " + size
                        + " < " + payload.length + ")";
            }
            if (!PayloadTempFile.hasZipLocalHeader(file)) {
                return "does not start with a ZIP local header (zip magic PK\\x03\\x04 missing)";
            }
            if (!tailMatches(file, payload)) {
                return "tail does not match the payload";
            }
            return null;
        } catch (Throwable t) {
            return "could not be verified (" + t.getClass().getSimpleName() + ")";
        }
    }

    /** Compares the last {@code payload.length} file bytes with {@code payload} in fixed chunks. */
    private static boolean tailMatches(Path file, byte[] payload) throws java.io.IOException {
        long size = Files.size(file);
        if (payload.length == 0 || size < payload.length) {
            return false;
        }
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
            channel.position(size - payload.length);
            ByteBuffer buffer = ByteBuffer.allocate(TAIL_COMPARE_CHUNK);
            int offset = 0;
            while (offset < payload.length) {
                buffer.clear();
                buffer.limit(Math.min(TAIL_COMPARE_CHUNK, payload.length - offset));
                int read = channel.read(buffer);
                if (read <= 0) {
                    return false;
                }
                if (!Arrays.equals(buffer.array(), 0, read, payload, offset, offset + read)) {
                    return false;
                }
                offset += read;
            }
            return true;
        }
    }

    private static Path defaultTempDirectory() {
        try {
            String value = System.getProperty("java.io.tmpdir");
            return value == null || value.isEmpty() ? null : Paths.get(value);
        } catch (Throwable t) {
            return null;
        }
    }

    private static Method findZeroArgStatic(Class<?> type, String name) {
        for (Method method : type.getDeclaredMethods()) {
            if (name.equals(method.getName())
                    && method.getParameterCount() == 0
                    && Modifier.isStatic(method.getModifiers())) {
                method.setAccessible(true);
                return method;
            }
        }
        return null;
    }

    private static Method findExtract(Class<?> type) {
        Method oneArg = null;
        Method noArg = null;
        for (Method method : type.getDeclaredMethods()) {
            if (!"nativePayloadExtract".equals(method.getName())
                    || !Modifier.isStatic(method.getModifiers())) {
                continue;
            }
            Class<?>[] parameters = method.getParameterTypes();
            if (parameters.length == 3 && parameters[0] == long.class
                    && parameters[1] == int.class && parameters[2] == int.class) {
                method.setAccessible(true);
                return method;
            }
            if (parameters.length == 1 && parameters[0] == long.class) {
                oneArg = method;
            } else if (parameters.length == 0) {
                noArg = method;
            }
        }
        Method chosen = oneArg != null ? oneArg : noArg;
        if (chosen != null) {
            chosen.setAccessible(true);
        }
        return chosen;
    }

    private static Object invoke(Method method, Object... arguments) {
        try {
            return method.invoke(null, arguments);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            }
            if (cause instanceof Error) {
                throw (Error) cause;
            }
            throw new IllegalStateException("native payload call failed", cause);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("native payload call failed", e);
        }
    }

    private static final class ReflectiveProbe implements NativeProbe {
        private final Method available;
        private final Method size;
        private final Method digest;
        private final Method extract;
        private final int extractArity;

        ReflectiveProbe(Method available, Method size, Method digest, Method extract) {
            this.available = available;
            this.size = size;
            this.digest = digest;
            this.extract = extract;
            this.extractArity = extract.getParameterCount();
        }

        @Override
        public boolean available() {
            Object value = invoke(available);
            if (value instanceof Boolean) {
                return (Boolean) value;
            }
            return value instanceof Number && ((Number) value).intValue() == 1;
        }

        @Override
        public long size() {
            Object value = invoke(size);
            return value instanceof Number ? ((Number) value).longValue() : 0L;
        }

        @Override
        public byte[] digest() {
            Object value = invoke(digest);
            return value instanceof byte[] ? (byte[]) value : null;
        }

        @Override
        public byte[] extract(long sessionHandle, int offset, int length) {
            Object result;
            if (extractArity == 3) {
                result = invoke(extract, sessionHandle, offset, length);
            } else if (extractArity == 1) {
                result = invoke(extract, sessionHandle);
            } else {
                result = invoke(extract);
            }
            if (!(result instanceof byte[])) {
                throw new IllegalStateException("nativePayloadExtract returned no bytes");
            }
            byte[] data = (byte[]) result;
            if (offset == 0 && data.length == length) {
                return data;
            }
            if (offset < 0 || length <= 0 || offset > data.length - length) {
                Arrays.fill(data, (byte) 0);
                throw new IllegalStateException("nativePayloadExtract returned " + data.length
                        + " bytes for range " + offset + "+" + length);
            }
            byte[] slice = Arrays.copyOfRange(data, offset, offset + length);
            Arrays.fill(data, (byte) 0);
            return slice;
        }
    }
}
