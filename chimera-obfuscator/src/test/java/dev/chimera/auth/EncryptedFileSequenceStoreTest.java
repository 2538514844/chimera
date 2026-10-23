package dev.chimera.auth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EncryptedFileSequenceStoreTest {

    private static SequenceState state(long sequence, String account, String hwid) {
        byte[] tokenHash = new byte[32];
        byte[] nonceHash = new byte[32];
        Arrays.fill(tokenHash, (byte) 0x11);
        Arrays.fill(nonceHash, (byte) 0x22);
        tokenHash[0] = (byte) sequence;
        return new SequenceState(SequenceState.VERSION, account, hwid, sequence, 1_760_000_000L,
                tokenHash, nonceHash);
    }

    @Test
    void savesLoadsAndSurvivesANewStoreInstance(@TempDir Path directory) throws Exception {
        EncryptedFileSequenceStore store = new EncryptedFileSequenceStore(directory);
        assertTrue(store.load().isEmpty());
        store.save(state(2, "account", "hwid"));

        Optional<SequenceState> loaded = store.load();
        assertTrue(loaded.isPresent());
        assertEquals(2L, loaded.get().sequence());
        assertEquals("account", loaded.get().account());

        EncryptedFileSequenceStore reopened = new EncryptedFileSequenceStore(directory);
        SequenceState fromDisk = reopened.load().orElseThrow();
        assertEquals(2L, fromDisk.sequence());
        assertArrayEquals(state(2, "account", "hwid").tokenHash(), fromDisk.tokenHash());
        assertArrayEquals(state(2, "account", "hwid").serverNonceHash(), fromDisk.serverNonceHash());
    }

    @Test
    void stateFileDoesNotContainPlaintextAccountOrHwid(@TempDir Path directory) throws Exception {
        EncryptedFileSequenceStore store = new EncryptedFileSequenceStore(directory);
        store.save(state(7, "secret-account-name", "secret-hwid-value"));
        byte[] file = Files.readAllBytes(directory.resolve("auth-seq.bin"));
        assertFalse(contains(file, "secret-account-name".getBytes(StandardCharsets.UTF_8)));
        assertFalse(contains(file, "secret-hwid-value".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void tamperedCiphertextFailsClosed(@TempDir Path directory) throws Exception {
        EncryptedFileSequenceStore store = new EncryptedFileSequenceStore(directory);
        store.save(state(3, "account", "hwid"));
        Path file = directory.resolve("auth-seq.bin");
        byte[] blob = Files.readAllBytes(file);
        blob[blob.length - 1] ^= 0x01;
        Files.write(file, blob);
        assertThrows(SequenceStoreException.class, store::load);
    }

    @Test
    void clearRemovesPersistedState(@TempDir Path directory) throws Exception {
        EncryptedFileSequenceStore store = new EncryptedFileSequenceStore(directory);
        store.save(state(1, "account", "hwid"));
        store.clear();
        assertTrue(store.load().isEmpty());
        assertFalse(Files.exists(directory.resolve("auth-seq.bin")));
    }

    @Test
    void corruptedKeyFileFailsAtStartup(@TempDir Path directory) throws Exception {
        Files.write(directory.resolve("auth-seq.key"), new byte[5]);
        assertThrows(SequenceStoreException.class, () -> new EncryptedFileSequenceStore(directory));
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }
}
