package dev.chimera.probe;

/**
 * Encrypted sentinel: its body only exists as CHENC1 ciphertext in the artifact, so a successful
 * load proves the attached transformer decrypted it at define time.
 */
public final class ChimeraSentinel {

    private ChimeraSentinel() {
    }

    public static boolean probe() {
        return true;
    }
}
