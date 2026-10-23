package dev.chimera.runtime;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Set;
import java.util.function.Consumer;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * S5 runtime staging file: a plaintext payload disguised as a throw-away library archive.
 *
 * <p>On-disk layout (nothing is encrypted here; the caller has already decrypted the payload):</p>
 * <pre>
 * [real ZIP: local header ... data.txt (random text) ... central directory ... EOCD][payload]
 *                                                                                   ^ tail
 * </pre>
 *
 * <p>The file is named {@code lib<16 lowercase hex>.zip}. The ZIP prefix is a genuine archive
 * containing one {@code data.txt} entry with random text, so a scanner that looks only at the
 * leading bytes sees an ordinary archive. The payload is appended verbatim after the archive as
 * its tail; a consumer recovers it by reading the last {@code payload.length} bytes. This mirrors
 * the Hachimi staging disguise.</p>
 *
 * <p>Fail-closed contract: invalid arguments, a missing/unwritable directory, a random-name
 * collision after {@value #MAX_NAME_ATTEMPTS} attempts, or any I/O failure delete the partial file
 * (with a {@code deleteOnExit} fallback) and raise {@link IOException}. The only state published
 * after a successful write is {@link #lastPath()}.</p>
 *
 * <p>Owner-only permissions are requested atomically on POSIX file systems ({@code rw-------});
 * on Windows the best-effort owner-only ACL fallback is applied. The file is never executable.</p>
 *
 * <p>Geometry note: because the payload follows the end-of-central-directory record, ZIP readers
 * that only scan a bounded tail window (for example {@link java.util.zip.ZipFile} looks back at
 * most ~64 KiB for the EOCD) enumerate the decoy archive only while the appended tail itself stays
 * inside that window. The PK header and archive prefix remain intact for any payload size; only
 * enumeration by such readers degrades. This matches the staging disguise, which always keeps the
 * payload at the very tail.</p>
 *
 * <p>This class has no nested types on purpose: {@code ChimeraEngine.RUNTIME_CLASSES} lists the
 * injected runtime classes explicitly, so adding a nested class would require a matching entry in
 * the engine's allow-list.</p>
 */
public final class PayloadTempFile {

    /** Decoy archive entry name. */
    public static final String DECOY_ENTRY_NAME = "data.txt";

    static final String NAME_PREFIX = "lib";
    static final String NAME_SUFFIX = ".zip";
    private static final int NAME_RANDOM_BYTES = 8;
    private static final int MAX_NAME_ATTEMPTS = 16;

    private static final int MIN_DECOY_BYTES = 512;
    private static final int MAX_DECOY_BYTES = 4096;
    private static final int DECOY_LINE_WIDTH = 72;
    private static final byte[] DECOY_ALPHABET =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-"
                    .getBytes(StandardCharsets.US_ASCII);

    private static final byte[] ZIP_LOCAL_HEADER = {0x50, 0x4b, 0x03, 0x04};
    private static final Set<PosixFilePermission> OWNER_ONLY = EnumSet.of(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
    private static final char[] HEX = "0123456789abcdef".toCharArray();
    private static final SecureRandom RNG = new SecureRandom();

    private static volatile Path lastPath;

    /**
     * Test-only seam: invoked with the fully written file, immediately before a successful write
     * publishes its path. Tests use it to inject an I/O failure or corrupt the staged bytes; it is
     * never set in production (and is package-private so the injected runtime cannot expose it).
     */
    static volatile Consumer<Path> postWriteHookForTests;

    private PayloadTempFile() {
    }

    /**
     * Writes {@code payload} as {@code lib<random>.zip} in {@code directory}.
     *
     * @param payload   plaintext bytes to append after the decoy ZIP; must be non-empty
     * @param directory existing directory that will hold the file
     * @return absolute path of the new file
     * @throws IOException when any argument is invalid or the file cannot be written; a partial
     *                     file is removed and scheduled for exit-time deletion when necessary
     */
    public static Path write(byte[] payload, Path directory) throws IOException {
        if (payload == null) {
            throw new IOException("payload must not be null");
        }
        if (payload.length == 0) {
            throw new IOException("payload must not be empty");
        }
        if (directory == null) {
            throw new IOException("payload directory must not be null");
        }
        if (!Files.isDirectory(directory)) {
            throw new IOException("payload directory is not a directory: " + directory);
        }

        Path file = null;
        try {
            file = createUniqueFile(directory);
            byte[] decoy = randomDecoy();
            try {
                writeZip(file, decoy);
            } finally {
                Arrays.fill(decoy, (byte) 0);
            }
            appendPayload(file, payload);
            applyOwnerOnlyPermissions(file);

            Consumer<Path> hook = postWriteHookForTests;
            if (hook != null) {
                hook.accept(file);
            }

            lastPath = file;
            return file;
        } catch (Throwable failure) {
            if (file != null) {
                deleteQuietly(file);
            }
            if (failure instanceof IOException) {
                throw (IOException) failure;
            }
            if (failure instanceof Error) {
                throw (Error) failure;
            }
            throw new IOException("payload staging file write failed", failure);
        }
    }

    /**
     * Best-effort deletion. Idempotent and never throws. Returns {@code true} when the file no
     * longer exists afterwards; otherwise it schedules an exit-time deletion and returns
     * {@code false}.
     */
    public static boolean deleteQuietly(Path path) {
        if (path == null) {
            return true;
        }
        try {
            Files.deleteIfExists(path);
        } catch (Throwable ignored) {
            // fall through: schedule an exit-time retry, then report the real state
        }
        boolean gone;
        try {
            gone = !Files.exists(path);
        } catch (Throwable t) {
            return false;
        }
        if (!gone) {
            try {
                path.toFile().deleteOnExit();
            } catch (Throwable ignored) {
                // nothing else we can do
            }
        }
        return gone;
    }

    /** Absolute path of the last successful write, or {@code null}. */
    public static Path lastPath() {
        return lastPath;
    }

    /** True when {@code path} starts with the PK\x03\x04 ZIP local-file header. */
    public static boolean hasZipLocalHeader(Path path) {
        if (path == null) {
            return false;
        }
        try (InputStream in = Files.newInputStream(path)) {
            byte[] header = new byte[ZIP_LOCAL_HEADER.length];
            int read = in.readNBytes(header, 0, header.length);
            return read == header.length
                    && header[0] == ZIP_LOCAL_HEADER[0]
                    && header[1] == ZIP_LOCAL_HEADER[1]
                    && header[2] == ZIP_LOCAL_HEADER[2]
                    && header[3] == ZIP_LOCAL_HEADER[3];
        } catch (Throwable t) {
            return false;
        }
    }

    /** Clears the diagnostic path and the test seam. Package-private test hook. */
    static void resetForTests() {
        lastPath = null;
        postWriteHookForTests = null;
    }

    // ------------------------------------------------------------------ internals

    private static Path createUniqueFile(Path directory) throws IOException {
        Path absoluteDirectory = directory.toAbsolutePath();
        for (int attempt = 0; attempt < MAX_NAME_ATTEMPTS; attempt++) {
            byte[] random = new byte[NAME_RANDOM_BYTES];
            RNG.nextBytes(random);
            Path candidate = absoluteDirectory.resolve(
                    NAME_PREFIX + hex(random) + NAME_SUFFIX);
            try {
                // Atomic owner-only creation on POSIX; Windows ignores the attribute view.
                return Files.createFile(candidate,
                        PosixFilePermissions.asFileAttribute(OWNER_ONLY));
            } catch (FileAlreadyExistsException ignored) {
                // extremely unlikely; retry with fresh randomness
            } catch (UnsupportedOperationException ignored) {
                try {
                    return Files.createFile(candidate);
                } catch (FileAlreadyExistsException retry) {
                    // retry with fresh randomness
                }
            }
        }
        throw new IOException("could not allocate a unique payload file name in "
                + absoluteDirectory);
    }

    private static byte[] randomDecoy() {
        int length = MIN_DECOY_BYTES + RNG.nextInt(MAX_DECOY_BYTES - MIN_DECOY_BYTES + 1);
        byte[] decoy = new byte[length];
        for (int i = 0; i < length; i++) {
            decoy[i] = (i > 0 && i % DECOY_LINE_WIDTH == 0)
                    ? (byte) '\n'
                    : DECOY_ALPHABET[RNG.nextInt(DECOY_ALPHABET.length)];
        }
        return decoy;
    }

    private static void writeZip(Path file, byte[] decoy) throws IOException {
        try (ZipOutputStream zip = new ZipOutputStream(
                new BufferedOutputStream(Files.newOutputStream(file,
                        StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)),
                StandardCharsets.UTF_8)) {
            ZipEntry entry = new ZipEntry(DECOY_ENTRY_NAME);
            entry.setTime(System.currentTimeMillis());
            zip.putNextEntry(entry);
            zip.write(decoy);
            zip.closeEntry();
        }
    }

    private static void appendPayload(Path file, byte[] payload) throws IOException {
        try (OutputStream out = new BufferedOutputStream(Files.newOutputStream(file,
                StandardOpenOption.WRITE, StandardOpenOption.APPEND))) {
            out.write(payload);
            out.flush();
        }
    }

    private static void applyOwnerOnlyPermissions(Path file) throws IOException {
        try {
            Files.setPosixFilePermissions(file, OWNER_ONLY);
            return;
        } catch (UnsupportedOperationException ignored) {
            // non-POSIX file system: use the File API fallback below
        } catch (IOException failure) {
            // cannot prove owner-only access: fail closed instead of exposing the payload
            throw new IOException("could not restrict payload file permissions", failure);
        }
        try {
            File target = file.toFile();
            target.setReadable(true, true);
            target.setWritable(true, true);
            target.setExecutable(false, false);
        } catch (Throwable ignored) {
            // Windows/provider ACLs cannot be verified through java.io.File; best effort only
        }
    }

    private static String hex(byte[] data) {
        char[] out = new char[data.length * 2];
        for (int i = 0; i < data.length; i++) {
            int value = data[i] & 0xff;
            out[i * 2] = HEX[value >>> 4];
            out[i * 2 + 1] = HEX[value & 0x0f];
        }
        return new String(out);
    }
}
