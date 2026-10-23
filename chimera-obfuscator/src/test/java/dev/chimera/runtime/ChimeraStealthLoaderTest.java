package dev.chimera.runtime;

import dev.chimera.transform.payload.StealthPayloadCodec;
import dev.chimera.transform.payload.StealthPayloadCodecTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Locale;
import java.util.Random;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * #24 payload-stealth runtime loader: Hachimi-shaped staging (lib*.zip + decoy data.txt + DLL +
 * random tail), reconstruction through the CHS1 codec, load hand-off, best-effort temp-file
 * deletion and fail-closed halt(4) on tamper. {@code System.load} itself is behind a test seam so
 * every step before the native call is covered; the real load is exercised offline against a
 * MinGW-built DLL (see docs/PAYLOAD-STEALTH-NOTES.md).
 */
class ChimeraStealthLoaderTest {

    @TempDir
    Path tempDir;

    @BeforeEach
    void resetState() {
        ChimeraStealthLoader.resetForTests();
    }

    @AfterEach
    void clearState() {
        ChimeraStealthLoader.resetForTests();
    }

    // ------------------------------------------------------------------ staging shape

    @Test
    void stagedFileIsADllImageWithRandomPadAndAZipTail() throws Exception {
        byte[] dll = StealthPayloadCodecTest.fakeDll(4096);

        byte[] staged = ChimeraStealthLoader.buildStagedFile(dll);

        assertTrue(staged.length > dll.length);
        assertEquals('M', staged[0], "DLL image must sit at offset 0 (Windows PE loader)");
        assertEquals('Z', staged[1]);
        assertArrayEquals(dll, Arrays.copyOfRange(staged, 0, dll.length),
                "DLL bytes must be staged verbatim at the file head");
        assertTrue(staged.length - dll.length >= 256,
                "random pad + zip tail after the DLL");
    }

    @Test
    void stagedFileWrittenToDiskOpensAsAZipArchiveWithOneEntry() throws Exception {
        byte[] dll = StealthPayloadCodecTest.fakeDll(2048);
        Path file = tempDir.resolve("staged.zip");
        Files.write(file, ChimeraStealthLoader.buildStagedFile(dll));

        // A zip reader scans back from the EOCD and sees ONLY data.txt; the DLL head is
        // "prepended data" to it, the same tolerance self-extracting archives rely on.
        try (ZipFile zip = new ZipFile(file.toFile())) {
            ZipEntry entry = zip.getEntry("data.txt");
            assertNotNull(entry, "decoy ZIP must contain data.txt");
            byte[] decoy = zip.getInputStream(entry).readAllBytes();
            assertTrue(decoy.length >= 512 && decoy.length <= 4096,
                    "decoy size: " + decoy.length);
        }
    }

    // ------------------------------------------------------------------ full materialise flow

    @Test
    void loadFromResourceStagesLoadsAndDeletesTheTempFile() throws Exception {
        byte[] dll = StealthPayloadCodecTest.fakeDll(2048);
        byte[] blob = StealthPayloadCodec.encode(dll, 128, null);
        Path resourceFile = writeResource(blob);

        ClassLoader isolated = new ResourceClassLoader(resourceFile);
        Class<?> clazz = Class.forName("dev.chimera.runtime.ChimeraStealthLoader", true, isolated);

        // Bridge the seams into the isolated class: the load op records the path handed to
        // System.load into the isolated lastLoadedPathForTests field, halt recording is OFF so a
        // successful run proves no halt fired, and a failure would surface as halt(4).
        Class<?> loadOpInterface = Class.forName(
                "dev.chimera.runtime.ChimeraStealthLoader$LoadOp", true, isolated);
        Object recorder = java.lang.reflect.Proxy.newProxyInstance(isolated,
                new Class[]{loadOpInterface},
                (proxy, method, args) -> {
                    java.lang.reflect.Field f = clazz.getDeclaredField("lastLoadedPathForTests");
                    f.setAccessible(true);
                    f.set(null, args[0]);
                    return null;
                });
        setStaticField(clazz, "loadOpForTests", recorder);
        setStaticField(clazz, "haltRecordingForTests", false);
        clazz.getMethod("ensureLoaded").invoke(null);

        int halt = readInt(clazz, "lastHaltCodeForTests");
        assertEquals(0, halt, "a valid payload must not halt");
        String path = readString(clazz, "lastLoadedPathForTests");
        assertNotNull(path, "the isolated loader must have handed a path to System.load");
        assertTrue(path.toLowerCase(Locale.ROOT).replace('\\', '/').contains("lib"),
                "temp name must use the lib prefix: " + path);
        assertTrue(path.toLowerCase(Locale.ROOT).endsWith(".zip"),
                "temp name must use the .zip suffix: " + path);
        assertFalse(Files.exists(Path.of(path)),
                "temp file must be deleted after a successful (seam) load");
    }

    @Test
    void ensureLoadedHaltsWhenResourceIsMissing() throws Exception {
        Path empty = Files.createTempFile(tempDir, "empty", ".dat");
        Files.deleteIfExists(empty);

        ClassLoader isolated = new ResourceClassLoader(empty);
        Class<?> clazz = Class.forName("dev.chimera.runtime.ChimeraStealthLoader", true, isolated);
        assertThrows(IllegalStateException.class,
                () -> runInIsolatedLoaderExpectingHalt(clazz));
        assertEquals(4, readInt(clazz, "lastHaltCodeForTests"),
                "missing resource must halt(4)");
    }

    @Test
    void ensureLoadedHaltsOnTamperedPayload() throws Exception {
        byte[] blob = StealthPayloadCodec.encode(StealthPayloadCodecTest.fakeDll(1024), 64, null);
        blob[StealthPayloadCodec.PREFIX_LENGTH + 5] ^= 0x11;  // break the CRC
        Path resourceFile = writeResource(blob);

        ClassLoader isolated = new ResourceClassLoader(resourceFile);
        Class<?> clazz = Class.forName("dev.chimera.runtime.ChimeraStealthLoader", true, isolated);
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> runInIsolatedLoaderExpectingHalt(clazz));
        assertTrue(failure.getMessage().contains("integrity") || "halt(4)".equals(failure.getMessage()),
                "tampered payload must fail the CRC check, got: " + failure.getMessage());
    }

    @Test
    void ensureLoadedHaltsOnGarbageResource() throws Exception {
        byte[] garbage = new byte[2048];
        new Random(1).nextBytes(garbage);
        Path resourceFile = writeResource(garbage);

        ClassLoader isolated = new ResourceClassLoader(resourceFile);
        Class<?> clazz = Class.forName("dev.chimera.runtime.ChimeraStealthLoader", true, isolated);
        assertThrows(IllegalStateException.class,
                () -> runInIsolatedLoaderExpectingHalt(clazz));
    }

    @Test
    void failureLeavesNoTempFileBehind() throws Exception {
        byte[] blob = StealthPayloadCodec.encode(StealthPayloadCodecTest.fakeDll(512), 16, null);
        blob[blob.length - 25] ^= 0x01;  // corrupt the trailer magic
        Path resourceFile = writeResource(blob);

        // C-6: the assertion is about what THIS run stages, so point java.io.tmpdir at the test's
        // own directory. Asserting on the machine-wide temp dir made the test fail whenever a real
        // client run had left a staged lib*.zip behind (Windows cannot unlink a mapped image).
        String previousTmp = System.getProperty("java.io.tmpdir");
        System.setProperty("java.io.tmpdir", tempDir.toString());
        try {
            ClassLoader isolated = new ResourceClassLoader(resourceFile);
            Class<?> clazz = Class.forName("dev.chimera.runtime.ChimeraStealthLoader", true, isolated);
            assertThrows(IllegalStateException.class,
                    () -> runInIsolatedLoaderExpectingHalt(clazz));

            assertEquals(0L, libZipCount(), "no lib*.zip residue in this run's temp dir");
        } finally {
            System.setProperty("java.io.tmpdir", previousTmp);
        }
    }

    @Test
    void sweeperDeletesStaleStagedImagesOnly() throws Exception {
        String previousTmp = System.getProperty("java.io.tmpdir");
        System.setProperty("java.io.tmpdir", tempDir.toString());
        try {
            // stale staged image: our prefix/suffix, big enough, MZ head, older than the age gate
            Path stale = tempDir.resolve(ChimeraStealthLoader.TEMP_PREFIX + "123"
                    + ChimeraStealthLoader.TEMP_SUFFIX);
            Files.write(stale, ChimeraStealthLoader.buildStagedFile(
                    StealthPayloadCodecTest.fakeDll(1_100_000)));
            Files.setLastModifiedTime(stale,
                    java.nio.file.attribute.FileTime.fromMillis(System.currentTimeMillis()
                            - ChimeraStealthLoader.STALE_AGE_MS - 60_000L));
            // fresh staged image: same shape but recent, must survive
            Path fresh = tempDir.resolve(ChimeraStealthLoader.TEMP_PREFIX + "456"
                    + ChimeraStealthLoader.TEMP_SUFFIX);
            Files.write(fresh, ChimeraStealthLoader.buildStagedFile(
                    StealthPayloadCodecTest.fakeDll(1_100_000)));
            // unrelated user file with the same name shape but no PE head, must survive
            Path userFile = tempDir.resolve(ChimeraStealthLoader.TEMP_PREFIX + "789"
                    + ChimeraStealthLoader.TEMP_SUFFIX);
            Files.write(userFile, new byte[1_200_000]);
            Files.setLastModifiedTime(userFile,
                    java.nio.file.attribute.FileTime.fromMillis(System.currentTimeMillis()
                            - ChimeraStealthLoader.STALE_AGE_MS - 60_000L));

            ChimeraStealthLoader.sweepStaleStaging();

            assertFalse(Files.exists(stale), "stale staged image must be swept");
            assertTrue(Files.exists(fresh), "recent staging must not be touched");
            assertTrue(Files.exists(userFile), "unrelated temp files must never be deleted");
        } finally {
            System.setProperty("java.io.tmpdir", previousTmp);
        }
    }

    // ------------------------------------------------------------------ helpers

    private Path writeResource(byte[] blob) throws IOException {
        Path file = Files.createTempFile(tempDir, "native", ".dat");
        Files.write(file, blob);
        return file;
    }

    /**
     * Runs {@code ChimeraStealthLoader.ensureLoaded()} inside {@code loader} so the resource is
     * resolved from the isolated class loader. The test seams (load op / halt recording) are
     * class-level state of the class in THIS loader, so the reflective helpers below bridge the
     * two class identities when needed. For the missing-resource case the loader halts; the halt
     * is translated to an IllegalStateException via the recording seam on the isolated class.
     */
    private void runInIsolatedLoader(Class<?> clazz) throws Exception {
        // Bridge the seams into the isolated class before running: the load op records the path
        // handed to System.load, and halt recording converts halt(4) into a visible failure.
        ClassLoader loader = clazz.getClassLoader();
        Class<?> loadOpInterface = Class.forName(
                "dev.chimera.runtime.ChimeraStealthLoader$LoadOp", true, loader);
        Object loadOp = java.lang.reflect.Proxy.newProxyInstance(loader,
                new Class[]{loadOpInterface},
                (proxy, method, args) -> {
                    java.lang.reflect.Field f = clazz.getDeclaredField("lastLoadedPathForTests");
                    f.setAccessible(true);
                    f.set(null, args[0]);
                    return null;
                });
        setStaticField(clazz, "loadOpForTests", loadOp);
        setStaticField(clazz, "haltRecordingForTests", true);
        clazz.getMethod("ensureLoaded").invoke(null);
        int halt = readInt(clazz, "lastHaltCodeForTests");
        if (halt == 4) {
            throw new IllegalStateException("halt(4) recorded by the isolated loader");
        }
    }

    private void runInIsolatedLoaderExpectingHalt(Class<?> clazz) throws Exception {
        // Halt recording on the isolated class converts halt into a normal return with code 4;
        // surface it as an exception for the assertions above.
        setStaticField(clazz, "haltRecordingForTests", true);
        clearLoadOp(clazz);
        clazz.getMethod("ensureLoaded").invoke(null);
        int halt = readInt(clazz, "lastHaltCodeForTests");
        if (halt != 4) {
            return;  // unexpected success: let the caller assert on the exception
        }
        throw new IllegalStateException("halt(4)");
    }

    private void clearLoadOp(Class<?> clazz) throws Exception {
        java.lang.reflect.Field field = clazz.getDeclaredField("loadOpForTests");
        field.setAccessible(true);
        field.set(null, null);
    }

    /** Accessible read helper: the isolated class is in the same package but a foreign loader. */
    private static int readInt(Class<?> clazz, String name) throws Exception {
        java.lang.reflect.Field field = clazz.getDeclaredField(name);
        field.setAccessible(true);
        return field.getInt(null);
    }

    private static String readString(Class<?> clazz, String name) throws Exception {
        java.lang.reflect.Field field = clazz.getDeclaredField(name);
        field.setAccessible(true);
        return (String) field.get(null);
    }

    private static void setStaticField(Class<?> clazz, String name, Object value) throws Exception {
        java.lang.reflect.Field field = clazz.getDeclaredField(name);
        field.setAccessible(true);
        field.set(null, value);
    }

    /**
     * Serves exactly one resource from a temp file so tests never touch the real jar. The target
     * class is defined in THIS loader (breaking parent delegation) so its
     * {@code getResourceAsStream} resolves against this loader's resource override, not the test
     * classpath where {@code /chimera/res/native.dat} does not exist.
     */
    static final class ResourceClassLoader extends ClassLoader {
        private static final String TARGET = "dev.chimera.runtime.ChimeraStealthLoader";
        private static final String TARGET_INTERNAL = "dev/chimera/runtime/ChimeraStealthLoader";

        private final Path resourceFile;

        ResourceClassLoader(Path resourceFile) {
            super(ChimeraStealthLoaderTest.class.getClassLoader());
            this.resourceFile = resourceFile;
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            synchronized (getClassLoadingLock(name)) {
                Class<?> loaded = findLoadedClass(name);
                if (loaded == null) {
                    if (TARGET.equals(name) || name.startsWith(TARGET + "$")) {
                        loaded = defineTarget(name);
                    } else {
                        return super.loadClass(name, resolve);
                    }
                }
                if (resolve) {
                    resolveClass(loaded);
                }
                return loaded;
            }
        }

        private Class<?> defineTarget(String binaryName) throws ClassNotFoundException {
            String internal = TARGET_INTERNAL
                    + binaryName.substring(TARGET.length()).replace('.', '$');
            // Class.getResourceAsStream-style names have no leading slash; ClassLoader-style
            // resource names do. Try both so the loader works under gradle's test runtime.
            java.io.InputStream in = getParent().getResourceAsStream(internal + ".class");
            if (in == null) {
                in = getParent().getResourceAsStream("/" + internal + ".class");
            }
            if (in == null) {
                throw new ClassNotFoundException(binaryName + " (test class bytes missing)");
            }
            try (java.io.InputStream source = in) {
                byte[] bytes = source.readAllBytes();
                return defineClass(binaryName, bytes, 0, bytes.length);
            } catch (IOException e) {
                throw new ClassNotFoundException(binaryName, e);
            }
        }

        @Override
        public java.io.InputStream getResourceAsStream(String name) {
            String wanted = "/" + ChimeraStealthLoader.RESOURCE_NAME;
            // Class.getResourceAsStream("/x") strips the slash before delegating, so both the
            // "/chimera/res/native.dat" and the "chimera/res/native.dat" forms must serve the
            // file for the isolated ChimeraStealthLoader to see it.
            if (name.equals(wanted) || name.equals(ChimeraStealthLoader.RESOURCE_NAME)) {
                try {
                    return Files.newInputStream(resourceFile);
                } catch (IOException e) {
                    return null;
                }
            }
            return super.getResourceAsStream(name);
        }
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private long libZipCount() throws IOException {
        Path tmp = Path.of(System.getProperty("java.io.tmpdir"));
        try (Stream<Path> files = Files.list(tmp)) {
            return files.filter(p -> {
                String n = p.getFileName().toString();
                return n.startsWith("lib") && n.endsWith(".zip");
            }).count();
        }
    }
}
