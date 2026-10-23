package dev.chimera.auth;

/**
 * Signature verification hook. Production wiring should pass a native/OpenSSL implementation
 * (see ChimeraRuntime.nativeVerifyAuth); the jdk implementation exists for tests and fallbacks.
 *
 * @param message             canonical bytes produced by {@link AuthTranscriptV4}
 * @param signature           raw Ed25519 signature (64 bytes)
 * @param ed25519PublicKeyRaw pinned server public key (32 raw bytes)
 */
@FunctionalInterface
public interface SignatureVerifier {
    boolean verify(byte[] message, byte[] signature, byte[] ed25519PublicKeyRaw);
}
