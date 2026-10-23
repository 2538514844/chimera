package dev.chimera.runtime;

import dev.chimera.transform.payload.StealthPayloadCodec;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Locale;
import java.util.Random;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * S5 payload-stealth runtime: Hachimi-shaped loader for the embedded native payload
 * (docs/HACHIMI-ARCH-vs-CHIMERA.md §3, issue #24).
 *
 * <p>Shape parity with the Hachimi {@code skidonion/quBCf/___} {@code <clinit>}:</p>
 * <ol>
 *   <li>read the disguised resource ({@code /chimera/res/native.dat}, no {@code .dll} suffix);</li>
 *   <li>{@link java.io.File#createTempFile(String, String)} with {@code "lib"} / {@code ".zip"}
 *       so the temp file name looks like a throwaway archive;</li>
 *   <li>write the reconstructed DLL bytes + a random pad + a real ZIP tail (one {@code data.txt}
 *       entry), so the temp file is not a bare DLL on disk: the PE loader reads the image at
 *       offset 0 while zip readers scan back from the EOCD and enumerate {@code data.txt};</li>
 *   <li>{@link System#load(String)} the temp file;</li>
 *   <li>best-effort delete the temp file immediately in a {@code finally} block.</li>
 * </ol>
 *
 * <p>Fail-closed: a missing resource, an invalid {@code CHS1} trailer, a CRC mismatch or any I/O
 * failure halts the JVM with exit code 4 (same semantics as {@link ChimeraAttach}) before the game
 * starts. There is no plaintext fallback: without the native image the protected runtime cannot
 * authenticate anything, so continuing would only hand out an unprotected session.</p>
 *
 * <p>Temp-file deletion note (Windows): after {@code System.load} the DLL is mapped into the
 * process; on NT an in-use mapped file usually cannot be deleted (sharing violation), and even
 * {@code deleteOnExit} runs its delete inside the dying JVM while the mapping is still held,
 * so on Windows the file can persist after the process exits. Hachimi deletes right after load
 * as well and relies on the same best-effort attempt; this loader mirrors that exactly: the
 * delete is attempted in {@code finally}, failures are swallowed silently and a
 * {@code deleteOnExit} fallback is registered before load (best-effort cleanup only, never
 * fatal). Verified with a real MinGW DLL: load succeeds from the staged {@code lib*.zip} and
 * the immediate delete fails on Windows as expected; the delete succeeds on the seam path
 * (covered by ChimeraStealthLoaderTest) and on unmapped-load failures.</p>
 *
 * <p>This class never touches {@link ChimeraEmbeddedNative}; the plain {@code --embed-dll}
 * path stays byte-identical for dev verification, and the engine picks which loader class to
 * inject based on {@code --payload-stealth}.</p>
 */
public final class ChimeraStealthLoader {

    /** Disguised resource name; must equal StealthPayloadCodec.DEFAULT_RESOURCE_NAME. */
    public static final String RESOURCE_NAME = StealthPayloadCodec.DEFAULT_RESOURCE_NAME;
    /** Temp-file prefix/suffix, Hachimi parity. */
    public static final String TEMP_PREFIX = "lib";
    public static final String TEMP_SUFFIX = ".zip";
    public static final String DECOY_ENTRY_NAME = "data.txt";

    /** C-6: staging deposits older than this are swept on the next start. */
    static final long STALE_AGE_MS = 10L * 60L * 1000L;

    private static final int MIN_TAIL_PAD = 256;
    private static final int MAX_TAIL_PAD = 2048;
    private static final int MIN_DECOY_BYTES = 512;
    private static final int MAX_DECOY_BYTES = 4096;
    private static final byte[] DECOY_ALPHABET =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-"
                    .getBytes(StandardCharsets.US_ASCII);

    // SECURITY (audit 2026-10-22 #3): the seams below are private and only honoured while the
    // build kept them (TEST_SEAMS, compiled out in every artifact that ships a native payload). A
    // third-party mod in the flat Fabric classloader can no longer reach them by declaring
    // dev.chimera.runtime, and reflection-set values are inert in a shipped jar.
    /**
     * Build-time seam switch: non-final on purpose so {@code dev.chimera.core.RuntimeSeamPatch}
     * can rewrite the {@code <clinit>} store while the class is copied into an artifact. Kept
     * local (instead of {@link ChimeraBuildFlags}) because tests define this class in an isolated
     * loader, where package-private access to another loader's class is illegal.
     */
    private static boolean TEST_SEAMS = true;

    /** Test seam: replaces System.load when set (never honoured in production). */
    private static volatile LoadOp loadOpForTests;
    /** Test seam: records the last path handed to System.load. */
    private static volatile String lastLoadedPathForTests;
    /** Test seam: when true, halt() is recorded instead of killing the JVM. */
    private static volatile boolean haltRecordingForTests;
    private static volatile int lastHaltCodeForTests;

    private ChimeraStealthLoader() {
    }

    /** True while the build-time seam switch is on (dev/test classpaths only). */
    private static boolean testSeams() {
        return TEST_SEAMS;
    }

    /** The System.load indirection used by tests. Public so isolated class loaders can proxy it. */
    @FunctionalInterface
    public interface LoadOp {
        void load(String path) throws Throwable;
    }

    /**
     * Fail-closed entry: materialise + load the stealth payload or halt(4). Never returns
     * normally unless the native image was actually loaded.
     */
    public static void ensureLoaded() {
        try {
            sweepStaleStaging();
            loadFromResource(RESOURCE_NAME);
        } catch (Throwable failure) {
            failClosed(failure);
        }
    }

    /**
     * C-6: self-healing cleanup of staging files a previous run could not delete.
     *
     * <p>On Windows a mapped image cannot be unlinked, so every run that loads the stealth payload
     * leaves one {@code lib*.zip} behind in {@code java.io.tmpdir} (12 runs = 153 MB of staged
     * VMP image observed on the build machine). A later start deletes the deposits an earlier start
     * could not, which shrinks the window in which the native image sits on disk in the clear.</p>
     *
     * <p>Deletion is deliberately conservative: only files matching this loader's prefix/suffix,
     * at least 1 MB, older than {@link #STALE_AGE_MS} and starting with an {@code MZ} image are
     * touched, so unrelated user files are never candidates. Every failure is swallowed: cleanup
     * must never break startup.</p>
     */
    static void sweepStaleStaging() {
        try {
            Path dir = Path.of(System.getProperty("java.io.tmpdir", "."));
            long now = System.currentTimeMillis();
            try (java.nio.file.DirectoryStream<Path> stream =
                         Files.newDirectoryStream(dir, TEMP_PREFIX + "*" + TEMP_SUFFIX)) {
                for (Path candidate : stream) {
                    try {
                        if (!Files.isRegularFile(candidate) || Files.size(candidate) < 1_000_000L) {
                            continue;
                        }
                        if (now - Files.getLastModifiedTime(candidate).toMillis() < STALE_AGE_MS) {
                            continue;
                        }
                        if (!startsWithMz(candidate)) {
                            continue;
                        }
                        Files.deleteIfExists(candidate);
                    } catch (Throwable ignored) {
                        // mapped by a running instance or protected: leave it for the next start
                    }
                }
            }
        } catch (Throwable ignored) {
            // cleanup is best effort
        }
    }

    private static boolean startsWithMz(Path candidate) {
        byte[] head = new byte[2];
        try (InputStream in = Files.newInputStream(candidate)) {
            if (in.readNBytes(head, 0, 2) != 2) {
                return false;
            }
        } catch (Throwable ignored) {
            return false;
        }
        return head[0] == 'M' && head[1] == 'Z';
    }

    /** Same as {@link #ensureLoaded()} with an explicit resource name (test hook). */
    static void loadFromResource(String resourceName) throws Exception {
        byte[] blob = readResource(resourceName);
        if (blob == null || blob.length == 0) {
            throw new IllegalStateException("stealth payload resource missing: " + resourceName);
        }
        // #9: the payload is the native image itself, so it is hashed against the build manifest
        // BEFORE it is decoded or handed to System.load. This is the first half of the two-stage
        // scheme: the manifest is not authenticated yet (its key is inside this very image), but a
        // payload that does not match the recorded digest can never be legitimate - the same
        // fail-closed rule the CHS1 CRC below already applies. The second half (HMAC over the whole
        // manifest, including this entry) runs from ChimeraRuntime right after the load.
        verifyPayloadManifest(resourceName, blob);
        byte[] dll = StealthPayloadCodec.decode(blob);
        if (dll == null) {
            // Covers magic/geometry failure and CRC failure: no distinguishable error so an
            // attacker tampering the resource learns nothing about which check fired.
            throw new IllegalStateException("stealth payload integrity check failed");
        }
        Path temp = java.io.File.createTempFile(TEMP_PREFIX, TEMP_SUFFIX).toPath();
        try {
            byte[] staged = buildStagedFile(dll);
            Files.write(temp, staged);
            temp.toFile().deleteOnExit();  // Windows mapped-file fallback; harmless elsewhere
            String absolute = temp.toAbsolutePath().toString();
            lastLoadedPathForTests = absolute;
            LoadOp op = testSeams() ? loadOpForTests : null;
            if (op != null) {
                try {
                    op.load(absolute);
                } catch (IOException | RuntimeException e) {
                    throw e;
                } catch (Throwable reflective) {
                    // LoadOp declares Throwable for the System.load mirror; narrow it here so
                    // loadFromResource can keep its checked IOException contract.
                    throw new IllegalStateException("native load failed", reflective);
                }
            } else {
                System.load(absolute);
            }
            // ChimeraRuntime resolves native ops through this property; the plain loader
            // (/chimera/embedded.dll) sets it too. Without it the staged stealth DLL loads but the
            // v4 session never binds to it, so release builds fall back to decoy strings.
            System.setProperty("chimera.native.auth.path", absolute);
        } finally {
            // Hachimi deletes right after load; on Windows a mapped DLL usually survives the
            // attempt, so this is best-effort and failures are silent (deleteOnExit covers it).
            deleteBestEffort(temp);
        }
    }

    /**
     * Builds the on-disk staging shape: {@code [DLL][random pad][real ZIP with data.txt]}.
     *
     * <p>Ordering note (verified against a real {@code System.load} on Windows NT): the Windows
     * PE loader requires the MZ header at offset 0, so a zip-first file fails with
     * "%1 is not a valid Win32 application". Hachimi's flow does the same thing: it copies the
     * native payload first and then APPENDS random bytes and the {@code data.txt} zip (§3
     * "拷贝 → 追加随机字节 + 一个内嵌 data.txt 的真 zip"). The zip at the tail gives the
     * file its disguise: the {@code lib*.zip} name plus a zip structure whose EOCD sits at the
     * end make every zip reader (Java {@link java.util.zip.ZipFile}, python zipfile, 7-Zip —
     * the same prepended-data tolerance self-extractors rely on) enumerate {@code data.txt},
     * while the PE loader reads the image at offset 0 and ignores the overlay. Both tool
     * families see exactly their own format.</p>
     */
    static byte[] buildStagedFile(byte[] dll) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(dll.length + 8192);
        out.writeBytes(dll);
        out.write(randomBytes(MIN_TAIL_PAD, MAX_TAIL_PAD));
        try (ZipOutputStream zip = new ZipOutputStream(out, StandardCharsets.UTF_8)) {
            ZipEntry entry = new ZipEntry(DECOY_ENTRY_NAME);
            entry.setTime(System.currentTimeMillis());
            zip.putNextEntry(entry);
            zip.write(randomText(MIN_DECOY_BYTES, MAX_DECOY_BYTES));
            zip.closeEntry();
        }
        return out.toByteArray();
    }

    /**
     * #9: expected SHA-256 hex for {@code name} from {@code /chimera/manifest.dat}, or {@code null}
     * when the manifest is absent (dev / {@code --no-integrity}) or does not list the entry (legacy
     * {@code CHM1} artifact). Never throws: a malformed manifest simply yields {@code null}, and the
     * authoritative check in {@link ChimeraRuntime#verifyResourceManifest()} rejects it afterwards.
     */
    static String expectedManifestHash(String name) {
        byte[] manifest;
        try {
            manifest = readResource("chimera/manifest.dat");
        } catch (IOException failure) {
            return null;
        }
        if (manifest == null || manifest.length == 0) {
            return null;
        }
        String[] lines = new String(manifest, StandardCharsets.UTF_8).split("\n", -1);
        if (lines.length == 0) {
            return null;
        }
        String header = lines[0].endsWith("\r")
                ? lines[0].substring(0, lines[0].length() - 1) : lines[0];
        if (!"CHM1".equals(header) && !"CHM2".equals(header)) {
            return null;
        }
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i].endsWith("\r")
                    ? lines[i].substring(0, lines[i].length() - 1) : lines[i];
            int separator = line.indexOf("  ");
            if (separator <= 0 || separator + 2 >= line.length()) {
                continue;
            }
            if (line.substring(separator + 2).equals(name)) {
                return line.substring(0, separator);
            }
        }
        return null;
    }

    /** #9: fail-closed when the payload does not match the digest recorded at build time. */
    static void verifyPayloadManifest(String resourceName, byte[] blob) {
        String expected = expectedManifestHash(resourceName);
        if (expected == null) {
            return;
        }
        String actual = sha256Hex(blob);
        if (!expected.equalsIgnoreCase(actual)) {
            failClosed(new IllegalStateException(
                    "payload does not match the build manifest: " + resourceName));
        }
    }

    static String sha256Hex(byte[] data) {
        try {
            return toHex(java.security.MessageDigest.getInstance("SHA-256").digest(data));
        } catch (java.security.GeneralSecurityException failure) {
            throw new IllegalStateException("sha-256 failed", failure);
        }
    }

    static String toHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            hex.append(Character.forDigit((value >> 4) & 0xF, 16));
            hex.append(Character.forDigit(value & 0xF, 16));
        }
        return hex.toString();
    }

    private static byte[] readResource(String name) throws IOException {
        // Class.getResourceAsStream("/x") delegates to the loader WITHOUT the slash; some
        // loaders (URLClassLoader subclasses, isolated test loaders) only serve the plain form.
        // Probe the slash form first, then the loader-relative form, so both the shipped jar
        // and the test harness resolve the payload.
        InputStream in = ChimeraStealthLoader.class.getResourceAsStream("/" + name);
        if (in == null) {
            in = ChimeraStealthLoader.class.getClassLoader().getResourceAsStream(name);
        }
        if (in == null) {
            return null;
        }
        try (InputStream source = in) {
            return source.readAllBytes();
        }
    }

    private static void deleteBestEffort(Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (Throwable ignored) {
            // mapped on Windows: deleteOnExit already registered, stay silent and non-fatal
        }
    }

    /** Halt(4) fail-closed semantics, aligned with ChimeraAttach. */
    private static void failClosed(Throwable failure) {
        String trace = String.valueOf(failure);
        try {
            java.io.StringWriter writer = new java.io.StringWriter();
            failure.printStackTrace(new java.io.PrintWriter(writer));
            trace = writer.toString();
        } catch (Throwable ignored) {
            // diagnostics only
        }
        System.err.println("[chimera] stealth native load failed (fail-closed): " + trace);
        if (haltRecordingForTests && testSeams()) {
            lastHaltCodeForTests = 4;
            return;
        }
        Runtime.getRuntime().halt(4);
    }

    private static byte[] randomText(int min, int max) {
        Random random = new Random();
        int length = min + random.nextInt(max - min + 1);
        byte[] out = new byte[length];
        for (int i = 0; i < length; i++) {
            out[i] = (i > 0 && i % 72 == 0)
                    ? (byte) '\n'
                    : DECOY_ALPHABET[random.nextInt(DECOY_ALPHABET.length)];
        }
        return out;
    }

    private static byte[] randomBytes(int min, int max) {
        Random random = new Random();
        byte[] out = new byte[min + random.nextInt(max - min + 1)];
        random.nextBytes(out);
        return out;
    }

    /** Test hook: reset all seams and records. */
    static void resetForTests() {
        loadOpForTests = null;
        lastLoadedPathForTests = null;
        haltRecordingForTests = false;
        lastHaltCodeForTests = 0;
    }

    /** Utility used by tests to wipe staged bytes. */
    static void wipe(byte[] data) {
        if (data != null) {
            Arrays.fill(data, (byte) 0);
        }
    }
}
