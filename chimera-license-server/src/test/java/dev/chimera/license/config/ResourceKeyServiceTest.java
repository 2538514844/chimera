package dev.chimera.license.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** ResourceKey persistence: generated once, encrypted at rest, reloadable, overridable by hex. */
class ResourceKeyServiceTest {

    private static final String MASTER_HEX =
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    private static final String RESOURCE_HEX =
            "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

    @Test
    void generatesPersistsEncryptedAndReloads(@TempDir Path dir) throws Exception {
        KeyStoreService keys = new KeyStoreService(dir.toString(), MASTER_HEX);
        ResourceKeyService first = new ResourceKeyService(keys, dir.toString(), "");
        byte[] key = first.resourceKey();
        assertEquals(32, key.length);

        Path file = dir.resolve("resource.key");
        assertTrue(Files.exists(file), "ResourceKey must be persisted on first start");
        assertEquals(65, Files.size(file), "magic(5) + nonce(12) + ciphertext(32+16)");
        byte[] blob = Files.readAllBytes(file);
        assertFalse(contains(blob, key), "the persisted file must not contain the plaintext key");

        ResourceKeyService reloaded = new ResourceKeyService(keys, dir.toString(), "");
        assertArrayEquals(key, reloaded.resourceKey(), "restart must reuse the persisted key");
        assertEquals(first.fingerprint(), reloaded.fingerprint());
        assertEquals(64, reloaded.fingerprint().length());
    }

    @Test
    void configuredHexTakesPriorityOverStoredFile(@TempDir Path dir) throws Exception {
        KeyStoreService keys = new KeyStoreService(dir.toString(), MASTER_HEX);
        ResourceKeyService generated = new ResourceKeyService(keys, dir.toString(), "");
        ResourceKeyService configured = new ResourceKeyService(keys, dir.toString(), RESOURCE_HEX);

        byte[] expected = HexFormat.of().parseHex(RESOURCE_HEX);
        assertArrayEquals(expected, configured.resourceKey());
        assertFalse(Arrays.equals(generated.resourceKey(), expected));
        assertEquals(64, configured.fingerprint().length());
    }

    @Test
    void invalidConfiguredHexIsRejected(@TempDir Path dir) throws Exception {
        KeyStoreService keys = new KeyStoreService(dir.toString(), MASTER_HEX);
        assertThrows(IllegalArgumentException.class,
                () -> new ResourceKeyService(keys, dir.toString(), "abcd"));
    }

    @Test
    void corruptedCiphertextFailsFast(@TempDir Path dir) throws Exception {
        KeyStoreService keys = new KeyStoreService(dir.toString(), MASTER_HEX);
        new ResourceKeyService(keys, dir.toString(), "");
        Path file = dir.resolve("resource.key");
        byte[] blob = Files.readAllBytes(file);
        blob[blob.length - 1] ^= 0x01;
        Files.write(file, blob);
        assertThrows(IllegalStateException.class,
                () -> new ResourceKeyService(keys, dir.toString(), ""),
                "a corrupted resource.key must not silently generate a new key");
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
