package dev.chimera.runtime;

import dev.chimera.crypto.Crypto;
import dev.chimera.transform.payload.PayloadPackager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.io.UncheckedIOException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * S5 runtime loader: round-trip through the packager, fail-closed native surface, tamper rejection,
 * random temp names and guaranteed cleanup.
 */
class ChimeraPayloadLoaderTest {

    private static final byte[] RESOURCE_KEY = Crypto.sha256("loader-test-key".getBytes(StandardCharsets.UTF_8));
    private static final byte[] ENV_SALT = Crypto.sha256("loader-env-salt".getBytes(StandardCharsets.UTF_8));
    private static final SecureRandom RANDOM = new SecureRandom();

    @TempDir
    Path tempDir;

    @BeforeEach
    void resetLoaderState() {
        ChimeraPayloadLoader.resetPoisonForTests();
        PayloadTempFile.resetForTests();
    }

    @AfterEach
    void clearRuntimePoisonFlag() {
        ChimeraPayloadLoader.resetPoisonForTests();
        PayloadTempFile.resetForTests();
        // Failure paths also poison ChimeraRuntime when it is on the classpath; clear that flag so
        // this test class cannot leak a poisoned runtime into later tests.
        resetRuntimePoisonQuietly();
    }

    @Test
    void packagedPayloadIsStagedAsZipDisguiseAndReleasedWithoutResidue() throws Exception {
        byte[] dll = random(4096);
        byte[] payload = random(8 * 1024);
        byte[] shipped = PayloadPackager.appendTo(dll, payload, RESOURCE_KEY, ENV_SALT);
        byte[] nativePlaintext = PayloadPackager.extract(shipped, RESOURCE_KEY, ENV_SALT);
        ChimeraPayloadLoader.NativeProbe probe = validProbe(nativePlaintext);

        String path = null;
        try {
            path = ChimeraPayloadLoader.loadNativePayload(42L, probe, tempDir);
            assertNotNull(path, () -> "load failed: " + ChimeraPayloadLoader.lastFailureReason());
            assertFalse(ChimeraPayloadLoader.isPoisoned());

            Path file = Paths.get(path);
            assertTrue(file.isAbsolute());
            assertTrue(file.startsWith(tempDir.toAbsolutePath()));
            assertTrue(Files.isRegularFile(file));
            assertTrue(file.getFileName().toString()
                    .matches("lib[0-9a-f]{16}\\.zip"), file.getFileName().toString());
            assertTrue(PayloadTempFile.hasZipLocalHeader(file));
            assertArrayEquals(payload, tail(file, payload.length));
            assertEquals(payload.length, ChimeraPayloadLoader.lastExtractedSize());
            assertArrayEquals(Crypto.sha256(nativePlaintext), ChimeraPayloadLoader.lastNativeDigest());
            assertEquals(path, ChimeraPayloadLoader.lastTempPath());
        } finally {
            ChimeraPayloadLoader.release(path);
        }

        assertFalse(Files.exists(Paths.get(path)));
        assertNoResidue();
    }

    @Test
    void nullNativeProbeFailsClosed() {
        assertNull(ChimeraPayloadLoader.loadNativePayload(1L, null, tempDir));
        assertTrue(ChimeraPayloadLoader.isPoisoned());
        assertTrue(ChimeraPayloadLoader.lastFailureReason().contains("API"));
        assertNoResidue();
    }

    @Test
    void unavailableOverlayFailsClosed() {
        ChimeraPayloadLoader.NativeProbe probe = new Probe(false, 1024,
                Crypto.sha256(new byte[1]), random(1024), false);

        assertNull(ChimeraPayloadLoader.loadNativePayload(1L, probe, tempDir));
        assertTrue(ChimeraPayloadLoader.isPoisoned());
        assertTrue(ChimeraPayloadLoader.lastFailureReason().contains("unavailable"));
        assertNoResidue();
    }

    @Test
    void extractFailureDoesNotEscapeAndLeavesNoTempFile() {
        ChimeraPayloadLoader.NativeProbe probe = new Probe(true, 4096,
                Crypto.sha256(new byte[1]), random(4096), true);

        String path = null;
        try {
            path = ChimeraPayloadLoader.loadNativePayload(7L, probe, tempDir);
        } catch (Throwable t) {
            throw new AssertionError("no throwable may escape the loader", t);
        }

        assertNull(path);
        assertTrue(ChimeraPayloadLoader.isPoisoned());
        assertNoResidue();
    }

    @Test
    void extractLengthMismatchFailsClosed() {
        ChimeraPayloadLoader.NativeProbe probe = new Probe(true, 4096,
                Crypto.sha256(new byte[1]), random(1024), false);

        assertNull(ChimeraPayloadLoader.loadNativePayload(1L, probe, tempDir));
        assertTrue(ChimeraPayloadLoader.isPoisoned());
        assertTrue(ChimeraPayloadLoader.lastFailureReason().contains("length"));
        assertNoResidue();
    }

    @Test
    void missingDigestFailsClosed() {
        ChimeraPayloadLoader.NativeProbe probe = new Probe(true, 1024, null, random(1024), false);

        assertNull(ChimeraPayloadLoader.loadNativePayload(1L, probe, tempDir));
        assertTrue(ChimeraPayloadLoader.isPoisoned());
        assertTrue(ChimeraPayloadLoader.lastFailureReason().contains("digest"));
        assertNoResidue();
    }

    @Test
    void oversizedPayloadFailsClosedBeforeExtraction() {
        ChimeraPayloadLoader.NativeProbe probe = new Probe(true,
                ChimeraPayloadLoader.MAX_PAYLOAD_BYTES + 1L,
                Crypto.sha256(new byte[1]), random(16), false);

        assertNull(ChimeraPayloadLoader.loadNativePayload(1L, probe, tempDir));
        assertTrue(ChimeraPayloadLoader.isPoisoned());
        assertTrue(ChimeraPayloadLoader.lastFailureReason().contains("size"));
        assertNoResidue();
    }

    @Test
    void tamperedOverlayFailsClosed() {
        byte[] shipped = PayloadPackager.appendTo(random(1024), random(2048),
                RESOURCE_KEY, ENV_SALT);
        PayloadPackager.OverlayLayout layout = PayloadPackager.locate(shipped);
        assertNotNull(layout);
        shipped[layout.ciphertextOffset() + 3] ^= 0x01;

        ChimeraPayloadLoader.NativeProbe probe = new ChimeraPayloadLoader.NativeProbe() {
            @Override
            public boolean available() {
                return true;
            }

            @Override
            public long size() {
                return layout.ciphertextLength();
            }

            @Override
            public byte[] digest() {
                return Crypto.sha256(new byte[1]);
            }

            @Override
            public byte[] extract(long sessionHandle, int offset, int length) {
                return PayloadPackager.extract(shipped, RESOURCE_KEY, ENV_SALT);
            }
        };

        assertNull(ChimeraPayloadLoader.loadNativePayload(1L, probe, tempDir));
        assertTrue(ChimeraPayloadLoader.isPoisoned());
        assertTrue(ChimeraPayloadLoader.lastFailureReason().contains("IllegalArgumentException"));
        assertNoResidue();
    }

    @Test
    void tempFileNamesAreRandomAndBothCanBeReleased() {
        byte[] payload = random(2048);
        ChimeraPayloadLoader.NativeProbe probe = validProbe(payload);

        String first = null;
        String second = null;
        try {
            first = ChimeraPayloadLoader.loadNativePayload(1L, probe, tempDir);
            second = ChimeraPayloadLoader.loadNativePayload(1L, probe, tempDir);
            assertNotNull(first);
            assertNotNull(second);
            assertNotEquals(first, second);
            assertTrue(Files.isRegularFile(Paths.get(first)));
            assertTrue(Files.isRegularFile(Paths.get(second)));
            assertTrue(Paths.get(first).getFileName().toString()
                    .matches("lib[0-9a-f]{16}\\.zip"));
            assertTrue(Paths.get(second).getFileName().toString()
                    .matches("lib[0-9a-f]{16}\\.zip"));
        } finally {
            ChimeraPayloadLoader.release(first);
            ChimeraPayloadLoader.release(second);
        }

        assertNoResidue();
    }

    @Test
    void releaseIsIdempotentAndTolerant() throws IOException {
        assertTrue(ChimeraPayloadLoader.release(null));
        assertTrue(ChimeraPayloadLoader.release(""));
        assertTrue(ChimeraPayloadLoader.release(tempDir.resolve("does-not-exist").toString()));

        Path file = Files.write(tempDir.resolve("residue-check.dll"), new byte[]{1, 2, 3});
        assertTrue(ChimeraPayloadLoader.release(file.toString()));
        assertFalse(Files.exists(file));
        assertTrue(ChimeraPayloadLoader.release(file.toString()));
        assertNoResidue();
    }

    @Test
    void poisonResetAllowsARetry() {
        assertNull(ChimeraPayloadLoader.loadNativePayload(1L, null, tempDir));
        assertTrue(ChimeraPayloadLoader.isPoisoned());

        ChimeraPayloadLoader.resetPoisonForTests();

        String path = null;
        try {
            path = ChimeraPayloadLoader.loadNativePayload(1L, validProbe(random(512)), tempDir);
            assertNotNull(path, () -> "retry failed: " + ChimeraPayloadLoader.lastFailureReason());
            assertFalse(ChimeraPayloadLoader.isPoisoned());
        } finally {
            ChimeraPayloadLoader.release(path);
        }
        assertNoResidue();
    }

    @Test
    void stagedFileIsARealZipWithRandomDataTxt() throws Exception {
        byte[] payload = random(4096);
        String path = null;
        try {
            path = ChimeraPayloadLoader.loadNativePayload(1L, validProbe(payload), tempDir);
            assertNotNull(path, () -> "load failed: " + ChimeraPayloadLoader.lastFailureReason());

            Path file = Paths.get(path);
            assertTrue(Files.size(file) > payload.length);
            try (ZipFile zip = new ZipFile(file.toFile())) {
                ZipEntry entry = zip.getEntry(PayloadTempFile.DECOY_ENTRY_NAME);
                assertNotNull(entry, "decoy archive must contain data.txt");
                assertTrue(entry.getSize() >= 512L, "decoy data.txt must have random content");
                try (InputStream in = zip.getInputStream(entry)) {
                    assertTrue(in.readAllBytes().length >= 512);
                }
            }
            assertArrayEquals(payload, tail(file, payload.length));
        } finally {
            ChimeraPayloadLoader.release(path);
        }
        assertNoResidue();
    }

    @Test
    void payloadIsRecoverableFromTheZipTailForSeveralSizes() throws Exception {
        for (int size : new int[]{1, 63, 512, 4096, 60000}) {
            byte[] payload = random(size);
            String path = null;
            try {
                path = ChimeraPayloadLoader.loadNativePayload(1L, validProbe(payload), tempDir);
                assertNotNull(path, () -> "load failed for " + size + " bytes: "
                        + ChimeraPayloadLoader.lastFailureReason());
                assertFalse(ChimeraPayloadLoader.isPoisoned());
                Path file = Paths.get(path);
                assertTrue(Files.size(file) > payload.length);
                assertTrue(PayloadTempFile.hasZipLocalHeader(file));
                assertArrayEquals(payload, tail(file, payload.length));
                assertEquals(payload.length, ChimeraPayloadLoader.lastExtractedSize());
            } finally {
                ChimeraPayloadLoader.release(path);
            }
        }
        assertNoResidue();
    }

    @Test
    void zipHeaderCorruptionFailsClosedAndCleansUp() {
        PayloadTempFile.postWriteHookForTests = ChimeraPayloadLoaderTest::corruptZipHeader;
        try {
            assertNull(ChimeraPayloadLoader.loadNativePayload(1L, validProbe(random(1024)), tempDir));
        } finally {
            PayloadTempFile.postWriteHookForTests = null;
        }
        assertTrue(ChimeraPayloadLoader.isPoisoned());
        String reason = ChimeraPayloadLoader.lastFailureReason();
        assertNotNull(reason);
        assertTrue(reason.contains("ZIP"), reason);
        assertNull(ChimeraPayloadLoader.lastTempPath());
        assertNoResidue();
    }

    @Test
    void truncatedStagedFileFailsClosedAndCleansUp() {
        PayloadTempFile.postWriteHookForTests = file -> truncateTo(file, 10L);
        try {
            assertNull(ChimeraPayloadLoader.loadNativePayload(1L, validProbe(random(2048)), tempDir));
        } finally {
            PayloadTempFile.postWriteHookForTests = null;
        }
        assertTrue(ChimeraPayloadLoader.isPoisoned());
        String reason = ChimeraPayloadLoader.lastFailureReason();
        assertNotNull(reason);
        assertTrue(reason.contains("shorter"), reason);
        assertNull(ChimeraPayloadLoader.lastTempPath());
        assertNoResidue();
    }

    @Test
    void tailCorruptionFailsClosedAndCleansUp() {
        PayloadTempFile.postWriteHookForTests = ChimeraPayloadLoaderTest::flipLastByte;
        try {
            assertNull(ChimeraPayloadLoader.loadNativePayload(1L, validProbe(random(2048)), tempDir));
        } finally {
            PayloadTempFile.postWriteHookForTests = null;
        }
        assertTrue(ChimeraPayloadLoader.isPoisoned());
        String reason = ChimeraPayloadLoader.lastFailureReason();
        assertNotNull(reason);
        assertTrue(reason.contains("tail"), reason);
        assertNull(ChimeraPayloadLoader.lastTempPath());
        assertNoResidue();
    }

    @Test
    void stagingWriteFailureFailsClosedAndCleansUp() {
        PayloadTempFile.postWriteHookForTests = file -> {
            throw new IllegalStateException("synthetic staging failure");
        };
        try {
            assertNull(ChimeraPayloadLoader.loadNativePayload(1L, validProbe(random(1024)), tempDir));
        } finally {
            PayloadTempFile.postWriteHookForTests = null;
        }
        assertTrue(ChimeraPayloadLoader.isPoisoned());
        String reason = ChimeraPayloadLoader.lastFailureReason();
        assertNotNull(reason);
        assertTrue(reason.contains("payload load failed"), reason);
        assertTrue(reason.contains("write failed"), reason);
        assertNull(ChimeraPayloadLoader.lastTempPath());
        assertNoResidue();
    }

    @Test
    void releaseRemovesStagedZipAndStaysIdempotent() {
        String path = null;
        try {
            path = ChimeraPayloadLoader.loadNativePayload(1L, validProbe(random(512)), tempDir);
            assertNotNull(path, () -> "load failed: " + ChimeraPayloadLoader.lastFailureReason());
            assertTrue(Files.isRegularFile(Paths.get(path)));
            assertTrue(ChimeraPayloadLoader.release(path));
            assertFalse(Files.exists(Paths.get(path)));
            assertTrue(ChimeraPayloadLoader.release(path));
        } finally {
            ChimeraPayloadLoader.release(path);
        }
        assertNoResidue();
    }

    @Test
    void reflectiveProbeFailsClosedWhenNativeSurfaceIsAbsent() {
        Assumptions.assumeTrue(ChimeraPayloadLoader.reflectiveProbe() == null,
                "native payload JNI methods are wired; the absent-surface path is covered by the null probe test");

        assertNull(ChimeraPayloadLoader.loadNativePayload());
        assertTrue(ChimeraPayloadLoader.isPoisoned());
        assertTrue(ChimeraPayloadLoader.lastFailureReason().contains("API"));
        assertNoResidue();
    }

    private ChimeraPayloadLoader.NativeProbe validProbe(byte[] plaintext) {
        return new Probe(true, plaintext.length, Crypto.sha256(plaintext), plaintext, false);
    }

    private static byte[] tail(Path file, int length) throws IOException {
        byte[] staged = Files.readAllBytes(file);
        assertTrue(staged.length >= length);
        return Arrays.copyOfRange(staged, staged.length - length, staged.length);
    }

    private static void corruptZipHeader(Path file) {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.WRITE)) {
            channel.write(ByteBuffer.wrap(new byte[]{'X', 'X', 'X', 'X'}), 0L);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static void truncateTo(Path file, long length) {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.WRITE)) {
            channel.truncate(length);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static void flipLastByte(Path file) {
        try (RandomAccessFile raf = new RandomAccessFile(file.toFile(), "rw")) {
            long position = raf.length() - 1L;
            raf.seek(position);
            int value = raf.read();
            raf.seek(position);
            raf.write(value ^ 0xff);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private void assertNoResidue() {
        try (Stream<Path> files = Files.list(tempDir)) {
            assertEquals(0L, files.count(), "temp payload files must not remain");
        } catch (IOException e) {
            throw new AssertionError("cannot list temp dir", e);
        }
    }

    private static void resetRuntimePoisonQuietly() {
        try {
            Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime");
            Field poisoned = runtime.getDeclaredField("poisoned");
            poisoned.setAccessible(true);
            poisoned.setBoolean(null, false);
        } catch (Throwable ignored) {
            // isolated compilation: the runtime class is not on the classpath
        }
    }

    private static byte[] random(int length) {
        byte[] out = new byte[length];
        RANDOM.nextBytes(out);
        return out;
    }

    private static final class Probe implements ChimeraPayloadLoader.NativeProbe {
        private final boolean available;
        private final long size;
        private final byte[] digest;
        private final byte[] payload;
        private final boolean throwOnExtract;

        Probe(boolean available, long size, byte[] digest, byte[] payload, boolean throwOnExtract) {
            this.available = available;
            this.size = size;
            this.digest = digest == null ? null : digest.clone();
            this.payload = payload == null ? null : payload.clone();
            this.throwOnExtract = throwOnExtract;
        }

        @Override
        public boolean available() {
            return available;
        }

        @Override
        public long size() {
            return size;
        }

        @Override
        public byte[] digest() {
            return digest == null ? null : digest.clone();
        }

        @Override
        public byte[] extract(long sessionHandle, int offset, int length) {
            if (throwOnExtract) {
                throw new IllegalStateException("synthetic native extract failure");
            }
            if (payload == null) {
                return null;
            }
            if (offset == 0 && length == payload.length) {
                return payload.clone();
            }
            if (offset < 0 || length <= 0 || offset > payload.length - length) {
                return new byte[0];
            }
            return Arrays.copyOfRange(payload, offset, offset + length);
        }
    }
}
