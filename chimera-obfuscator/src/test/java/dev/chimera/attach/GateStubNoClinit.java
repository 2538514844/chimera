package dev.chimera.attach;

/**
 * Test fixture for {@link ClassGateInjectorTest}: a class with <b>no</b> {@code <clinit>}, so the
 * injector must leave it byte-for-byte unchanged (adding an initializer would change class
 * initialization semantics).
 */
public final class GateStubNoClinit {

    private GateStubNoClinit() {
    }

    public static int value() {
        return 7;
    }
}
