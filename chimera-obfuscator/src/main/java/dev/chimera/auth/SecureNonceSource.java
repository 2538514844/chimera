package dev.chimera.auth;

import java.security.SecureRandom;

/** Thread-safe SecureRandom-backed nonce source. */
public final class SecureNonceSource implements NonceSource {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    public byte[] nextBytes(int length) {
        if (length < 1) {
            throw new IllegalArgumentException("length must be >= 1");
        }
        byte[] out = new byte[length];
        RANDOM.nextBytes(out);
        return out;
    }
}
