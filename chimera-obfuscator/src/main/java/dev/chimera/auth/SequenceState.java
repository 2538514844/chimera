package dev.chimera.auth;

/** Persisted monotonic v4 session state; authenticated at rest by the sequence store. */
public record SequenceState(int version, String account, String hwid, long sequence, long issuedAt,
                            byte[] tokenHash, byte[] serverNonceHash) {

    public static final int VERSION = 1;

    public SequenceState {
        if (version != VERSION) {
            throw new IllegalArgumentException("unsupported sequence state version: " + version);
        }
        if (account == null || account.isEmpty() || hwid == null || hwid.isEmpty()) {
            throw new IllegalArgumentException("account/hwid must not be empty");
        }
        if (sequence < 1 || issuedAt < 0) {
            throw new IllegalArgumentException("invalid sequence/issuedAt");
        }
        if (tokenHash == null || tokenHash.length != 32
                || serverNonceHash == null || serverNonceHash.length != 32) {
            throw new IllegalArgumentException("token/nonce hashes must be 32 bytes");
        }
        tokenHash = tokenHash.clone();
        serverNonceHash = serverNonceHash.clone();
    }

    @Override
    public byte[] tokenHash() {
        return tokenHash.clone();
    }

    @Override
    public byte[] serverNonceHash() {
        return serverNonceHash.clone();
    }
}
