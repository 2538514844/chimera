package dev.chimera.attach;

/**
 * Test fixture for {@link ClassGateInjectorTest}: a class with a {@code <clinit>} whose gate method
 * denies. The injector rewrites the initializer to call {@code nativeGateCheck(id)}.
 *
 * <p>In the product the denial path is a native {@code std::_Exit(4)} - the DLL never returns a
 * verdict to Java. That cannot be asserted in a unit test (it would kill the test JVM), so this
 * fixture throws instead: what is verified here is that the injected prologue really runs before
 * the original {@code <clinit>} body and that its denial aborts initialization.</p>
 */
public final class GateStubDeny {

    public static boolean initialized;

    static {
        initialized = true;
    }

    private GateStubDeny() {
    }

    /** Same shape as {@code ChimeraRuntime.nativeGateCheck(int)}: deny = abort initialization. */
    public static void nativeGateCheck(int id) {
        throw new IllegalStateException("chimera: class gate denied id=" + id);
    }
}
