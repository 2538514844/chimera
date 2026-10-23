package dev.chimera.integrity;

import dev.chimera.core.ChimeraConfig;
import dev.chimera.core.ChimeraEngine;
import dev.chimera.crypto.Crypto;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * B6/KI-28: every hidden-class chunk must be accompanied by a ResourceKey-sealed build-time hash
 * of its plaintext class bytes; the runtime opens it through native op9 (or the Java fallback)
 * before defineHiddenClass and poisons on a mismatch. A Frida hook that replaces the class byte[]
 * argument is exactly this test's threat.
 *
 * <p>Frida end-to-end validation (hook defineHiddenClass) is NOT executed here; see
 * docs/PHASE-B3-B6-REPORT.md and docs/FRIDA-STATUS.md.</p>
 */
class HiddenChunkIntegrityTest {

    private static final String CONTENT_KEY = "test-content-key";
    private static final byte[] KEY = Crypto.sha256(CONTENT_KEY.getBytes(StandardCharsets.UTF_8));
    /** KI-28: outer sealed chunk-hash record magic ("CHB2"). */
    private static final int CHUNK_HASH_SEALED_MAGIC = 0x43484232;
    /** magic(4) + nonce(12) + AES-GCM(41-byte record)[60] = 76 bytes. */
    private static final int CHUNK_HASH_RECORD_LENGTH = 4 + 12 + 44 + 16;

    @AfterEach
    void clearKey() {
        System.clearProperty("chimera.contentKey");
    }

    @Test
    void everyChunkGetsAnAuthenticatedHashRecord(@TempDir Path work) throws Exception {
        Path jar = buildProtectedJar(work);

        int bins = 0;
        int hashes = 0;
        byte[] firstHash = null;
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            var entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (!entry.getName().startsWith("chimera/chunks/chunk_")) continue;
                if (entry.getName().endsWith(".bin")) bins++;
                if (entry.getName().endsWith(".hash")) {
                    hashes++;
                    if (firstHash == null) {
                        try (InputStream in = zip.getInputStream(entry)) {
                            firstHash = in.readAllBytes();
                        }
                    }
                }
            }
        }
        assertTrue(bins > 0, "expected at least one encrypted hidden-class chunk");
        assertEquals(bins, hashes, "every chunk must have exactly one hash record");
        assertNotNull(firstHash);
        assertEquals(CHUNK_HASH_RECORD_LENGTH, firstHash.length,
                "CHB2 record = magic(4) + nonce(12) + AES-GCM(44 plaintext + 16 tag)");
        assertEquals(CHUNK_HASH_SEALED_MAGIC, ByteBuffer.wrap(firstHash).getInt(0));

        System.setProperty("chimera.contentKey", Crypto.hex(KEY));
        try (URLClassLoader loader = open(jar)) {
            Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true, loader);
            Class<?> bonus = Class.forName("fixtures.Bonus", true, loader);
            Object instance = bonus.getDeclaredConstructor().newInstance();
            assertEquals(52, ((Integer) bonus.getMethod("calc", int.class).invoke(instance, 7)).intValue(),
                    "a valid authenticated chunk hash must not disturb execution");
            assertEquals(Boolean.TRUE, runtime.getMethod("isKeyHealthy").invoke(null));
        }
    }

    @Test
    void tamperedHashRecordPoisonsBeforeDefineHiddenClass(@TempDir Path work) throws Exception {
        Path original = buildProtectedJar(work);
        Path tampered = work.resolve("hash-tampered.jar");
        boolean[] rewritten = {false};
        try (ZipFile in = new ZipFile(original.toFile());
             ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(tampered))) {
            var entries = in.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                byte[] data;
                try (InputStream stream = in.getInputStream(entry)) { data = stream.readAllBytes(); }
                if (!rewritten[0] && entry.getName().startsWith("chimera/chunks/chunk_")
                        && entry.getName().endsWith(".hash")) {
                    data = data.clone();
                    data[16] ^= 0x01; // corrupt the AEAD nonce/ciphertext: the seal must fail
                    rewritten[0] = true;
                }
                out.putNextEntry(new ZipEntry(entry.getName()));
                out.write(data);
                out.closeEntry();
            }
        }
        assertTrue(rewritten[0], "test setup must find a chunk hash record");
        assertPoisons(tampered, "tampered chunk hash must fail closed");
    }

    @Test
    void missingHashRecordPoisonsBeforeDefineHiddenClass(@TempDir Path work) throws Exception {
        Path original = buildProtectedJar(work);
        Path stripped = work.resolve("hash-missing.jar");
        boolean[] removed = {false};
        try (ZipFile in = new ZipFile(original.toFile());
             ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(stripped))) {
            var entries = in.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.getName().startsWith("chimera/chunks/chunk_")
                        && entry.getName().endsWith(".hash")) {
                    removed[0] = true;
                    continue;
                }
                byte[] data;
                try (InputStream stream = in.getInputStream(entry)) { data = stream.readAllBytes(); }
                out.putNextEntry(new ZipEntry(entry.getName()));
                out.write(data);
                out.closeEntry();
            }
        }
        assertTrue(removed[0], "test setup must find a chunk hash record");
        assertPoisons(stripped, "missing chunk hash must fail closed");
    }

    // ------------------------------------------------------------------ helpers

    private static Path buildProtectedJar(Path work) throws Exception {
        Path input = work.resolve("fixtures.jar");
        try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(input))) {
            for (String name : new String[]{"fixtures/Bonus.class", "fixtures/Lic.class"}) {
                try (InputStream in = HiddenChunkIntegrityTest.class.getClassLoader().getResourceAsStream(name)) {
                    assertNotNull(in, "missing fixture " + name);
                    out.putNextEntry(new ZipEntry(name));
                    out.write(in.readAllBytes());
                    out.closeEntry();
                }
            }
        }
        Path output = work.resolve("fixtures-obf.jar");
        ChimeraConfig config = new ChimeraConfig();
        config.inputJar = input;
        config.outputJar = output;
        config.keyMaterial = KEY;
        config.nativeOutDir = work.resolve("native");
        config.integrityManifest = true;
        new ChimeraEngine(config).run();
        return output;
    }

    private static URLClassLoader open(Path jar) throws Exception {
        return new URLClassLoader(new URL[]{jar.toUri().toURL()}, ClassLoader.getPlatformClassLoader());
    }

    private static void assertPoisons(Path jar, String message) throws Exception {
        System.setProperty("chimera.contentKey", Crypto.hex(KEY));
        try (URLClassLoader loader = open(jar)) {
            Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true, loader);
            Class<?> bonus = Class.forName("fixtures.Bonus", true, loader);
            Object instance = bonus.getDeclaredConstructor().newInstance();
            Object value = bonus.getMethod("calc", int.class).invoke(instance, 7);
            assertNotEquals(52, ((Integer) value).intValue(), message);
            assertEquals(Boolean.FALSE, runtime.getMethod("isKeyHealthy").invoke(null), message);
        }
    }
}
