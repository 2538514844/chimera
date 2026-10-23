package dev.chimera.license.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * #19 watermark key pair: RSA-3072, generated on first start and kept under
 * {@code license.key-dir} next to the signing key.
 *
 * <p>The <b>public</b> key is baked into the client DLL at build time ({@code -DCHIMERA_WM_PUBKEY_B64}),
 * so the client can seal the per-licence payload but nobody can read it. The <b>private</b> key never
 * leaves the server: it is what turns a leaked jar back into "licence X was running this build".
 * Losing it means every watermark already shipped becomes unreadable, so back it up with the
 * signing key.</p>
 */
@Component
public class WatermarkKeyService {

    private static final Logger LOG = LoggerFactory.getLogger(WatermarkKeyService.class);
    private static final int RSA_BITS = 3072;

    private final KeyPair keyPair;

    public WatermarkKeyService(@Value("${license.key-dir:data/keys}") String keyDir) throws IOException {
        Path directory = Path.of(keyDir);
        Files.createDirectories(directory);
        this.keyPair = loadOrGenerate(directory);
        LOG.info("watermark public key (base64, bake into the client with -WmPubKeyB64): {}",
                publicKeyBase64());
    }

    private static KeyPair loadOrGenerate(Path directory) throws IOException {
        Path privatePath = directory.resolve("wm-rsa.pk8");
        Path publicPath = directory.resolve("wm-rsa.pub");
        if (Files.exists(privatePath)) {
            if (!Files.exists(publicPath)) {
                throw new IOException("wm-rsa.pub missing next to wm-rsa.pk8");
            }
            try {
                // RSA, not the Ed25519 helper: CryptoUtils.privateKeyFromPkcs8 is Ed25519-only and
                // rejects an RSA key with "Unsupported OID 1.2.840.113549.1.1.1" (found on the
                // second start, when the load path runs instead of the generate path).
                PrivateKey privateKey = KeyFactory.getInstance("RSA")
                        .generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(privatePath)));
                PublicKey publicKey = KeyFactory.getInstance("RSA")
                        .generatePublic(new X509EncodedKeySpec(Files.readAllBytes(publicPath)));
                return new KeyPair(publicKey, privateKey);
            } catch (IOException e) {
                throw e;
            } catch (Exception e) {
                throw new IOException("cannot load watermark RSA key", e);
            }
        }
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(RSA_BITS);
            KeyPair generated = generator.generateKeyPair();
            Files.write(privatePath, generated.getPrivate().getEncoded());
            Files.write(publicPath, generated.getPublic().getEncoded());
            restrict(privatePath);
            LOG.info("generated new watermark RSA-{} key pair under {}", RSA_BITS,
                    directory.toAbsolutePath());
            return generated;
        } catch (Exception e) {
            throw new IOException("cannot generate watermark RSA key", e);
        }
    }

    /** X.509/SPKI DER of the public key, Base64 (no line breaks) - the value the client bakes in. */
    public String publicKeyBase64() {
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }

    /** Server-side only: decrypts a {@code CHMW1:} payload recovered from a leaked build. */
    public PrivateKey privateKey() {
        return keyPair.getPrivate();
    }

    private static void restrict(Path path) {
        try {
            Files.setPosixFilePermissions(path,
                    java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException | IOException ignored) {
            // Windows / non-POSIX: best effort only
        }
    }
}
