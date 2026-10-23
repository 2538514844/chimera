package dev.chimera.auth;

/** Source of CSPRNG bytes for {@code client_nonce}; injectable for deterministic tests. */
@FunctionalInterface
public interface NonceSource {
    byte[] nextBytes(int length);
}
