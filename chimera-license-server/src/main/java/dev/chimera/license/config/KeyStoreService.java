package dev.chimera.license.config;

import dev.chimera.license.crypto.CryptoUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

/**
 * Loads (or generates on first run) the two long-lived server secrets:
 * <ul>
 *   <li>the Ed25519 signing key pair used to sign license responses;</li>
 *   <li>the product-level 32-byte <b>MasterKey</b> used to derive per-account UserContentKeys.</li>
 * </ul>
 *
 * <p>The global content key is no longer delivered to clients (B-Full lite): activation derives
 * {@code UserContentKey = HKDF-SHA256(MasterKey, salt="chimera/uck/v1", info=BE64(account_id)||hwid)}
 * and wraps that value. The MasterKey itself never leaves the server. The native client must
 * implement the same derivation; see README and docs/known-issues.md (KI-28).</p>
 *
 * <p>The private key and MasterKey live under {@code license.key-dir} (default {@code data/keys}).
 * Production should replace this file-based storage with a KMS/HSM; see README.</p>
 */
@Component
public class KeyStoreService {

    private static final Logger LOG = LoggerFactory.getLogger(KeyStoreService.class);

    private final KeyPair signingKeyPair;
    private final byte[] masterKey;

    public KeyStoreService(@Value("${license.key-dir:data/keys}") String keyDir,
                           @Value("${license.content-key-hex:}") String masterKeyHex) throws IOException {
        Path directory = Path.of(keyDir);
        Files.createDirectories(directory);
        this.signingKeyPair = loadOrGenerateSigningKey(directory);
        this.masterKey = loadOrGenerateMasterKey(directory, masterKeyHex);
        LOG.info("license signing public key (base64, bake into client): {}",
                CryptoUtils.b64(CryptoUtils.rawEd25519(signingKeyPair.getPublic())));
        LOG.info("master key sha256 fingerprint (never log the key itself): {}",
                CryptoUtils.hex(CryptoUtils.sha256(masterKey)).substring(0, 16));
    }

    private static KeyPair loadOrGenerateSigningKey(Path directory) throws IOException {
        Path privatePath = directory.resolve("ed25519.pk8");
        Path publicPath = directory.resolve("ed25519.pub");
        if (Files.exists(privatePath)) {
            try {
                if (!Files.exists(publicPath)) {
                    throw new IOException("ed25519.pub missing next to ed25519.pk8");
                }
                PrivateKey privateKey = CryptoUtils.privateKeyFromPkcs8(Files.readAllBytes(privatePath));
                PublicKey publicKey = java.security.KeyFactory.getInstance("Ed25519")
                        .generatePublic(new X509EncodedKeySpec(Files.readAllBytes(publicPath)));
                return new KeyPair(publicKey, privateKey);
            } catch (IOException e) {
                throw e;
            } catch (Exception e) {
                throw new IOException("cannot load Ed25519 key", e);
            }
        }
        KeyPair generated = CryptoUtils.ed25519KeyPair();
        Files.write(privatePath, generated.getPrivate().getEncoded(), java.nio.file.StandardOpenOption.CREATE,
                java.nio.file.StandardOpenOption.TRUNCATE_EXISTING);
        Files.write(publicPath, generated.getPublic().getEncoded(), java.nio.file.StandardOpenOption.CREATE,
                java.nio.file.StandardOpenOption.TRUNCATE_EXISTING);
        restrict(privatePath);
        restrict(publicPath);
        LOG.info("generated new Ed25519 signing key pair under {}", directory.toAbsolutePath());
        return generated;
    }

    private static byte[] loadOrGenerateMasterKey(Path directory, String hex) throws IOException {
        if (hex != null && !hex.isBlank()) {
            if (!hex.matches("[0-9a-fA-F]{64}")) {
                throw new IllegalArgumentException("license.content-key-hex must be 64 hex characters");
            }
            return decodeHex(hex);
        }
        Path contentPath = directory.resolve("content.key");
        if (Files.exists(contentPath)) {
            byte[] data = Files.readAllBytes(contentPath);
            if (data.length != CryptoUtils.KEY_32) {
                throw new IOException("content.key must be 32 bytes, found " + data.length);
            }
            return data;
        }
        byte[] generated = CryptoUtils.random(CryptoUtils.KEY_32);
        Files.write(contentPath, generated);
        restrict(contentPath);
        LOG.info("generated new server MasterKey at {}", contentPath.toAbsolutePath());
        return generated;
    }

    private static byte[] decodeHex(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static void restrict(Path path) {
        try {
            Files.setPosixFilePermissions(path, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException | IOException ignored) {
            // Windows / non-POSIX: best effort only
        }
    }

    public PrivateKey signingPrivateKey() {
        return signingKeyPair.getPrivate();
    }

    public String publicKeyBase64() {
        return CryptoUtils.b64(CryptoUtils.rawEd25519(signingKeyPair.getPublic()));
    }

    /** Server-side only. Never log, serialize or put this into a response. */
    public byte[] masterKey() {
        return masterKey.clone();
    }

    /** Derives the UserContentKey that is delivered inside {@code wrapped_ck} for one device. */
    public byte[] deriveUserContentKey(long accountId, String hwid) {
        return CryptoUtils.deriveUserContentKey(masterKey, accountId, hwid);
    }

    public byte[] sign(byte[] message) {
        return CryptoUtils.ed25519Sign(signingKeyPair.getPrivate(), message);
    }

    /** First 16 bytes of SHA-256(MasterKey), for key/build correlation only. */
    public byte[] fingerprint() {
        byte[] digest = CryptoUtils.sha256(masterKey);
        byte[] shortDigest = new byte[16];
        System.arraycopy(digest, 0, shortDigest, 0, shortDigest.length);
        return shortDigest;
    }
}
