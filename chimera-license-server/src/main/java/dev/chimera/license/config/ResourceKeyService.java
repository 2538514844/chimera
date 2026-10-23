package dev.chimera.license.config;

import dev.chimera.license.crypto.CryptoUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;

/**
 * Holds the long-lived 32-byte <b>ResourceKey</b> that the build pipeline uses to encrypt paid
 * resources and that activation delivers inside the signed {@code resource_ck} envelope.
 *
 * <p>Source priority:</p>
 * <ol>
 *   <li>{@code CHIMERA_RESOURCE_KEY_HEX} / {@code license.resource-key-hex} (64 hex) — recommended
 *       for fleets and for keeping the build host and the server in sync;</li>
 *   <li>{@code data/keys/resource.key} — generated on first start and stored AES-256-GCM encrypted
 *       with a KEK derived from the server MasterKey:
 *       {@code KEK = HKDF-SHA256(MasterKey, salt=UTF8("chimera/resource-kek/v1"),
 *       info=UTF8("resource-key"), L=32)}; file = {@code "CHRK1" || 12B nonce || ciphertext(32B+16B tag)}.</li>
 * </ol>
 *
 * <p>The ResourceKey itself is never logged; only its SHA-256 fingerprint is. The MasterKey is never
 * delivered to clients. Build hosts obtain the ResourceKey either from the same
 * {@code CHIMERA_RESOURCE_KEY_HEX} configuration or from
 * {@code GET /api/v1/license/resource-key} authenticated with {@code X-Chimera-Build-Token}.</p>
 */
@Component
public class ResourceKeyService {

    private static final Logger LOG = LoggerFactory.getLogger(ResourceKeyService.class);

    private static final byte[] FILE_MAGIC = "CHRK1".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] KEK_SALT = "chimera/resource-kek/v1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] KEK_INFO = "resource-key".getBytes(StandardCharsets.UTF_8);
    private static final byte[] FILE_AAD = "chimera/resource-key-file/v1".getBytes(StandardCharsets.UTF_8);
    private static final int GCM_NONCE_BYTES = 12;
    private static final int GCM_TAG_BYTES = 16;
    private static final int KEY_BYTES = 32;

    private final byte[] resourceKey;

    public ResourceKeyService(KeyStoreService keys,
                              @Value("${license.key-dir:data/keys}") String keyDir,
                              @Value("${license.resource-key-hex:}") String resourceKeyHex) throws IOException {
        Path directory = Path.of(keyDir);
        Files.createDirectories(directory);
        this.resourceKey = loadOrGenerate(keys.masterKey(), directory.resolve("resource.key"), resourceKeyHex);
        LOG.info("resource key sha256 fingerprint (build resources must use this key): {}",
                fingerprint().substring(0, 16));
    }

    private static byte[] loadOrGenerate(byte[] masterKey, Path file, String hex) throws IOException {
        if (hex != null && !hex.isBlank()) {
            if (!hex.matches("[0-9a-fA-F]{64}")) {
                throw new IllegalArgumentException("license.resource-key-hex must be 64 hex characters");
            }
            return decodeHex(hex);
        }
        byte[] kek = CryptoUtils.hkdf(masterKey, KEK_SALT, KEK_INFO, KEY_BYTES);
        try {
            if (Files.exists(file)) {
                return decryptStoredKey(file, kek);
            }
            byte[] generated = CryptoUtils.random(KEY_BYTES);
            byte[] nonce = CryptoUtils.random(GCM_NONCE_BYTES);
            byte[] ciphertext = CryptoUtils.aesGcmEncrypt(kek, nonce, generated, FILE_AAD);
            ByteArrayOutputStream blob = new ByteArrayOutputStream(FILE_MAGIC.length + nonce.length + ciphertext.length);
            blob.writeBytes(FILE_MAGIC);
            blob.writeBytes(nonce);
            blob.writeBytes(ciphertext);
            Files.write(file, blob.toByteArray(), StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
            restrict(file);
            LOG.info("generated new ResourceKey at {}", file.toAbsolutePath());
            return generated;
        } finally {
            Arrays.fill(kek, (byte) 0);
        }
    }

    private static byte[] decryptStoredKey(Path file, byte[] kek) throws IOException {
        byte[] blob = Files.readAllBytes(file);
        int expected = FILE_MAGIC.length + GCM_NONCE_BYTES + KEY_BYTES + GCM_TAG_BYTES;
        if (blob.length != expected) {
            throw new IOException("resource.key has unexpected length " + blob.length + " (expected " + expected + ")");
        }
        for (int i = 0; i < FILE_MAGIC.length; i++) {
            if (blob[i] != FILE_MAGIC[i]) {
                throw new IOException("resource.key has invalid magic");
            }
        }
        byte[] nonce = Arrays.copyOfRange(blob, FILE_MAGIC.length, FILE_MAGIC.length + GCM_NONCE_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(blob, FILE_MAGIC.length + GCM_NONCE_BYTES, blob.length);
        try {
            byte[] key = CryptoUtils.aesGcmDecrypt(kek, nonce, ciphertext, FILE_AAD);
            if (key.length != KEY_BYTES) {
                throw new IOException("resource.key decrypted to " + key.length + " bytes");
            }
            return key;
        } catch (RuntimeException e) {
            throw new IllegalStateException(
                    "cannot decrypt " + file.toAbsolutePath()
                            + " with the current MasterKey; restore the original MasterKey or "
                            + "set CHIMERA_RESOURCE_KEY_HEX explicitly", e);
        }
    }

    private static void restrict(Path file) {
        try {
            Files.setPosixFilePermissions(file,
                    java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException | IOException ignored) {
            // Windows / non-POSIX: best effort only
        }
    }

    private static byte[] decodeHex(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    /** Server-side only. Used to wrap resource_ck; must never be logged or sent in clear text. */
    public byte[] resourceKey() {
        return resourceKey.clone();
    }

    public String resourceKeyBase64() {
        return CryptoUtils.b64(resourceKey);
    }

    /** Full SHA-256 hex fingerprint for build correlation / admin endpoint. */
    public String fingerprint() {
        return CryptoUtils.hex(CryptoUtils.sha256(resourceKey));
    }
}
