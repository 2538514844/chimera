package dev.chimera.attach;

/**
 * Test fixture for {@link ClassGateInjectorTest}: same as {@link GateStubDeny} but the gate allows,
 * so the rewritten initializer must complete normally.
 */
public final class GateStubAllow {

    public static boolean initialized;

    static {
        initialized = true;
    }

    private GateStubAllow() {
    }

    /** Same shape as {@code ChimeraRuntime.nativeGateCheck(int)}: allow = no-op. */
    public static void nativeGateCheck(int id) {
        // allowed
    }
}
