package dev.chimera.auth;

import java.time.Clock;
import java.util.Objects;

/** Immutable configuration for {@link AuthProtocolV4}. */
public final class AuthV4Config {

    public static final long DEFAULT_CLOCK_SKEW_SECONDS = 300L;
    public static final int DEFAULT_NONCE_BYTES = 32;
    public static final int DEFAULT_HISTORY_LIMIT = 64;

    private final long clockSkewSeconds;
    private final int nonceBytes;
    private final int historyLimit;
    private final Clock clock;
    private final NonceSource nonceSource;
    private final SignatureVerifier signatureVerifier;
    private final SequenceStore sequenceStore;

    private AuthV4Config(Builder builder) {
        this.clockSkewSeconds = builder.clockSkewSeconds;
        this.nonceBytes = builder.nonceBytes;
        this.historyLimit = builder.historyLimit;
        this.clock = builder.clock;
        this.nonceSource = builder.nonceSource;
        this.signatureVerifier = builder.signatureVerifier;
        this.sequenceStore = builder.sequenceStore;
    }

    public long clockSkewSeconds() {
        return clockSkewSeconds;
    }

    public int nonceBytes() {
        return nonceBytes;
    }

    public int historyLimit() {
        return historyLimit;
    }

    public Clock clock() {
        return clock;
    }

    public NonceSource nonceSource() {
        return nonceSource;
    }

    public SignatureVerifier signatureVerifier() {
        return signatureVerifier;
    }

    public SequenceStore sequenceStore() {
        return sequenceStore;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private long clockSkewSeconds = DEFAULT_CLOCK_SKEW_SECONDS;
        private int nonceBytes = DEFAULT_NONCE_BYTES;
        private int historyLimit = DEFAULT_HISTORY_LIMIT;
        private Clock clock = Clock.systemUTC();
        private NonceSource nonceSource = new SecureNonceSource();
        private SignatureVerifier signatureVerifier = JdkSignatureVerifier.INSTANCE;
        private SequenceStore sequenceStore;

        public Builder clockSkewSeconds(long value) {
            if (value < 0 || value > 86_400L) {
                throw new IllegalArgumentException("clockSkewSeconds out of range: " + value);
            }
            this.clockSkewSeconds = value;
            return this;
        }

        public Builder nonceBytes(int value) {
            if (value < 16 || value > 64) {
                throw new IllegalArgumentException("nonceBytes must be 16..64: " + value);
            }
            this.nonceBytes = value;
            return this;
        }

        public Builder historyLimit(int value) {
            if (value < 8 || value > 4096) {
                throw new IllegalArgumentException("historyLimit must be 8..4096: " + value);
            }
            this.historyLimit = value;
            return this;
        }

        public Builder clock(Clock value) {
            this.clock = Objects.requireNonNull(value, "clock");
            return this;
        }

        public Builder nonceSource(NonceSource value) {
            this.nonceSource = Objects.requireNonNull(value, "nonceSource");
            return this;
        }

        public Builder signatureVerifier(SignatureVerifier value) {
            this.signatureVerifier = Objects.requireNonNull(value, "signatureVerifier");
            return this;
        }

        public Builder sequenceStore(SequenceStore value) {
            this.sequenceStore = Objects.requireNonNull(value, "sequenceStore");
            return this;
        }

        public AuthV4Config build() {
            if (sequenceStore == null) {
                throw new IllegalStateException("sequenceStore is required for replay protection");
            }
            return new AuthV4Config(this);
        }
    }
}
