package dev.chimera.runtime;

/**
 * Single entry point for materialising the native payload.
 *
 * <p>Historically four call sites each decided "stealth blob or plain embedded.dll?" on their own,
 * and one of them ({@code ChimeraMainBootstrap}) skipped the decision entirely and called
 * {@link ChimeraEmbeddedNative} directly. In a stealth build that later call saw
 * {@code required == true} with no {@code /chimera/embedded.dll} and halted a healthy artifact
 * after the gate had already authorised.</p>
 *
 * <p>Now the decision is made once, here, and every caller goes through it. Ordering is explicit:
 * whoever runs first loads the payload; everyone else is a no-op.</p>
 */
final class ChimeraPayload {

    private static volatile boolean loaded;

    private ChimeraPayload() {
    }

    static void ensureLoaded() {
        if (loaded) {
            return;
        }
        synchronized (ChimeraPayload.class) {
            if (loaded) {
                return;
            }
            if (ChimeraPayload.class.getResource("/" + ChimeraStealthLoader.RESOURCE_NAME) != null) {
                ChimeraStealthLoader.ensureLoaded();
            } else {
                ChimeraEmbeddedNative.ensureLoaded();
            }
            loaded = true;
        }
    }
}
