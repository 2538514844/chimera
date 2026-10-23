package dev.chimera.attach;

/** Shared state of the attached agent; the mod bootstrap reads it reflectively. */
public final class AgentState {

    /** True once the transformer is registered. */
    public static volatile boolean installed;
    /** Number of class bodies successfully decrypted. */
    public static volatile int decrypted;
    /** Number of decryption failures (a non-zero value must abort startup). */
    public static volatile int failures;
    /** Key fingerprint (SHA-256 prefix of the derived key) for diagnostics only. */
    public static volatile String keyId = "";

    private AgentState() {
    }
}
