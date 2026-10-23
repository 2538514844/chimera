package dev.chimera.auth;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

/** JDK-only Ed25519 verifier used by tests and as a compatibility fallback. */
public final class JdkSignatureVerifier implements SignatureVerifier {

    public static final JdkSignatureVerifier INSTANCE = new JdkSignatureVerifier();

    private static final byte[] ED25519_SPKI_PREFIX = {
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
    };

    private JdkSignatureVerifier() {
    }

    @Override
    public boolean verify(byte[] message, byte[] signature, byte[] ed25519PublicKeyRaw) {
        if (message == null || signature == null || signature.length != 64
                || ed25519PublicKeyRaw == null || ed25519PublicKeyRaw.length != 32) {
            return false;
        }
        try {
            byte[] encoded = new byte[ED25519_SPKI_PREFIX.length + ed25519PublicKeyRaw.length];
            System.arraycopy(ED25519_SPKI_PREFIX, 0, encoded, 0, ED25519_SPKI_PREFIX.length);
            System.arraycopy(ed25519PublicKeyRaw, 0, encoded, ED25519_SPKI_PREFIX.length,
                    ed25519PublicKeyRaw.length);
            PublicKey publicKey = KeyFactory.getInstance("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(encoded));
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(publicKey);
            verifier.update(message);
            return verifier.verify(signature);
        } catch (RuntimeException | java.security.GeneralSecurityException e) {
            return false;
        }
    }
}