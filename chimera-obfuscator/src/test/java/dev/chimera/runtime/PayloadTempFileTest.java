package dev.chimera.runtime;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Set;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * S5 staging disguise: a real ZIP decoy ({@code data.txt}) with the plaintext payload appended as
 * its tail, random {@code lib<hex>.zip} names, owner-only permissions and fail-closed cleanup.
 */
class PayloadTempFileTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @TempDir
    Path tempDir;

    @BeforeEach
    void resetState() {
        PayloadTempFile.resetForTests();
    }

    @AfterEach
    void clearState() {
        PayloadTempFile.resetForTests();
    }

    @Test
    void writeCreatesRealZipWithRandomDataTxtAndPayloadTail() throws Exception {
        byte[] payload = random(2048);

        Path file = PayloadTempFile.write(payload, tempDir);

        assertNotNull(file);
        assertTrue(file.isAbsolute());
        assertTrue(file.startsWith(tempDir.toAbsolutePath()));
        assertTrue(Files.isRegularFile(file));
        assertTrue(file.getFileName().toString().matches("lib[0-9a-f]{16}\\.zip"),
                file.getFileName().toString());
        assertTrue(PayloadTempFile.hasZipLocalHeader(file));
        assertTrue(Files.size(file) > payload.length);
        assertArrayEquals(payload, tail(file, payload.length));
        assertEquals(file, PayloadTempFile.lastPath());

        try (ZipFile zip = new ZipFile(file.toFile())) {
            ZipEntry entry = zip.getEntry(PayloadTempFile.DECOY_ENTRY_NAME);
            assertNotNull(entry, "decoy ZIP must contain data.txt");
            try (InputStream in = zip.getInputStream(entry)) {
                byte[] decoy = in.readAllBytes();
                assertTrue(decoy.length >= 512 && decoy.length <= 4096, "decoy size: " + decoy.length);
            }
        }
    }

    @Test
    void payloadIsRecoverableFromTheTailAfterTheZipDirectory() throws Exception {
        byte[] payload = random(60000);

        Path file = PayloadTempFile.write(payload, tempDir);

        byte[] staged = Files.readAllBytes(file);
        assertTrue(staged.length > payload.length);
        assertArrayEquals(payload, Arrays.copyOfRange(staged,
                staged.length - payload.length, staged.length));
        assertTrue(PayloadTempFile.hasZipLocalHeader(file));
    }

    @Test
    void fileNamesAreRandomAndZipShaped() throws IOException {
        Path first = PayloadTempFile.write(random(256), tempDir);
        Path second = PayloadTempFile.write(random(256), tempDir);
        Path third = PayloadTempFile.write(random(256), tempDir);

        assertNotEquals(first, second);
        assertNotEquals(second, third);
        assertNotEquals(first, third);
        assertTrue(first.getFileName().toString().matches("lib[0-9a-f]{16}\\.zip"));
        assertTrue(second.getFileName().toString().matches("lib[0-9a-f]{16}\\.zip"));
        assertTrue(third.getFileName().toString().matches("lib[0-9a-f]{16}\\.zip"));
        assertEquals(third, PayloadTempFile.lastPath());

        assertTrue(PayloadTempFile.deleteQuietly(first));
        assertTrue(PayloadTempFile.deleteQuietly(second));
        assertTrue(PayloadTempFile.deleteQuietly(third));
        assertNoStagingFiles();
    }

    @Test
    void deleteQuietlyIsIdempotentAndNullSafe() throws IOException {
        assertTrue(PayloadTempFile.deleteQuietly(null));
        assertTrue(PayloadTempFile.deleteQuietly(tempDir.resolve("does-not-exist.zip")));

        Path file = PayloadTempFile.write(random(64), tempDir);
        assertTrue(PayloadTempFile.deleteQuietly(file));
        assertFalse(Files.exists(file));
        assertTrue(PayloadTempFile.deleteQuietly(file));
        assertTrue(PayloadTempFile.deleteQuietly(file));
        assertNoStagingFiles();
    }

    @Test
    void writeRejectsInvalidArgumentsWithoutCreatingStagingFiles() throws IOException {
        assertThrows(IOException.class, () -> PayloadTempFile.write(null, tempDir));
        assertThrows(IOException.class, () -> PayloadTempFile.write(new byte[0], tempDir));
        assertThrows(IOException.class, () -> PayloadTempFile.write(random(8), null));

        Path notDirectory = Files.write(tempDir.resolve("not-a-dir"), new byte[]{1});
        assertThrows(IOException.class, () -> PayloadTempFile.write(random(8), notDirectory));

        assertNoStagingFiles();
        assertTrue(Files.exists(notDirectory));
        assertNull(PayloadTempFile.lastPath());
    }

    @Test
    void writeFailureRemovesThePartialFileAndKeepsThePreviousPath() throws IOException {
        Path previous = PayloadTempFile.write(random(128), tempDir);
        assertEquals(previous, PayloadTempFile.lastPath());

        PayloadTempFile.postWriteHookForTests = file -> {
            throw new IllegalStateException("synthetic staging failure");
        };
        try {
            IOException failure = assertThrows(IOException.class,
                    () -> PayloadTempFile.write(random(256), tempDir));
            assertTrue(failure.getMessage().contains("write failed"), failure.getMessage());
        } finally {
            PayloadTempFile.postWriteHookForTests = null;
        }

        assertEquals(previous, PayloadTempFile.lastPath());
        assertTrue(Files.isRegularFile(previous));
        assertEquals(1L, stagingFileCount());
        assertNoStagingFilesAfterDelete(previous);
    }

    @Test
    void resetForTestsClearsThePublishedPathAndTheHook() throws IOException {
        Path file = PayloadTempFile.write(random(64), tempDir);
        assertEquals(file, PayloadTempFile.lastPath());

        PayloadTempFile.resetForTests();

        assertNull(PayloadTempFile.lastPath());
        assertNull(PayloadTempFile.postWriteHookForTests);
    }

    @Test
    void writePublishesOnlyAfterTheWholePayloadIsAppended() throws IOException {
        byte[] payload = random(1024);
        PayloadTempFile.postWriteHookForTests = file -> {
            try {
                assertTrue(Files.size(file) > payload.length,
                        "hook runs only after the payload tail is complete");
                assertArrayEquals(payload, tail(file, payload.length));
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        };
        Path file = null;
        try {
            file = PayloadTempFile.write(payload, tempDir);
            assertTrue(Files.isRegularFile(file));
        } finally {
            PayloadTempFile.postWriteHookForTests = null;
            PayloadTempFile.deleteQuietly(file);
        }
        assertNoStagingFiles();
    }

    @Test
    void ownerOnlyPermissionsAreAppliedWhenPosixIsSupported() throws IOException {
        Path file = PayloadTempFile.write(random(64), tempDir);

        Assumptions.assumeTrue(
                Files.getFileStore(file).supportsFileAttributeView(PosixFileAttributeView.class),
                "non-POSIX file system; the File-API fallback is applied instead");

        Set<PosixFilePermission> expected = EnumSet.of(
                PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
        assertEquals(expected, Files.getPosixFilePermissions(file));
        PayloadTempFile.deleteQuietly(file);
    }

    private static byte[] tail(Path file, int length) throws IOException {
        byte[] staged = Files.readAllBytes(file);
        assertTrue(staged.length >= length);
        return Arrays.copyOfRange(staged, staged.length - length, staged.length);
    }

    private static byte[] random(int length) {
        byte[] data = new byte[length];
        RANDOM.nextBytes(data);
        return data;
    }

    private long stagingFileCount() throws IOException {
        try (Stream<Path> files = Files.list(tempDir)) {
            return files.filter(path -> path.getFileName().toString().startsWith("lib"))
                    .count();
        }
    }

    private void assertNoStagingFilesAfterDelete(Path file) throws IOException {
        assertTrue(PayloadTempFile.deleteQuietly(file));
        assertEquals(0L, stagingFileCount());
    }

    private void assertNoStagingFiles() throws IOException {
        assertEquals(0L, stagingFileCount(), "no lib*.zip staging files may remain");
    }
}
