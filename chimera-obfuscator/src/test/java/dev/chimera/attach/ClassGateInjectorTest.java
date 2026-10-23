package dev.chimera.attach;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A2: a gated class must refuse to initialize when the gate denies, and initialize normally when
 * it allows. Both cases are checked by actually initializing the rewritten class, so a broken
 * {@code <clinit>} (bad frames, bad max_stack) fails here instead of in a player's game.
 */
class ClassGateInjectorTest {

    @Test
    void clinitThrowsWhenGateReturnsZero() throws Exception {
        byte[] original = readClass("dev/chimera/attach/GateStubDeny.class");
        byte[] gated = ClassGateInjector.injectWithId(original, 42,
                "dev/chimera/attach/GateStubDeny");
        assertNotSame(original, gated);
        assertTrue(gated.length > original.length, "prologue must be injected");

        Class<?> defined = new Loader().define("dev.chimera.attach.GateStubDeny", gated);
        assertNotNull(defined);
        // Initialization runs the injected prologue: the gate denies -> initialization aborts.
        // (In the product the DLL exits the process; the fixture throws so the test JVM survives.)
        assertThrows(ExceptionInInitializerError.class,
                () -> Class.forName("dev.chimera.attach.GateStubDeny", true,
                        defined.getClassLoader()));
    }

    @Test
    void clinitCompletesWhenGateAllows() throws Exception {
        byte[] original = readClass("dev/chimera/attach/GateStubAllow.class");
        byte[] gated = ClassGateInjector.injectWithId(original, 42,
                "dev/chimera/attach/GateStubAllow");
        assertNotSame(original, gated);

        Class<?> defined = new Loader().define("dev.chimera.attach.GateStubAllow", gated);
        Class<?> initialized = Class.forName("dev.chimera.attach.GateStubAllow", true,
                defined.getClassLoader());
        assertNotNull(initialized.getDeclaredField("initialized"));
    }

    @Test
    void classWithoutClinitIsLeftAlone() throws Exception {
        // No static initializer -> nothing to gate (adding one would change init semantics).
        byte[] original = readClass("dev/chimera/attach/GateStubNoClinit.class");
        assertSame(original, ClassGateInjector.injectWithId(original, 1,
                "dev/chimera/attach/GateStubNoClinit"));
    }

    @Test
    void selectionIsDeterministicAndRare() {
        int hits = 0;
        for (int i = 0; i < 1000; i++) {
            if (ClassGateInjector.selected("dev/idhammai/mod/modules/impl/C" + i)) {
                hits++;
            }
        }
        // MODULUS is 50 in the gray build, so ~2% of 1000 names must be selected.
        assertTrue(hits >= 10 && hits <= 30, "expected roughly 1/50 of classes, got " + hits);
        assertTrue(ClassGateInjector.idFor("a") > 0);
    }

    private static byte[] readClass(String resource) throws Exception {
        try (InputStream in = ClassGateInjector.class.getResourceAsStream("/" + resource)) {
            assertNotNull(in, "class resource missing: " + resource);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) > 0) {
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        }
    }

    /** Defines the rewritten bytes locally (no parent delegation for the stub names). */
    private static final class Loader extends ClassLoader {
        Loader() {
            super(ClassGateInjectorTest.class.getClassLoader());
        }

        Class<?> define(String name, byte[] bytes) {
            return defineClass(name, bytes, 0, bytes.length);
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            synchronized (getClassLoadingLock(name)) {
                Class<?> existing = findLoadedClass(name);
                if (existing == null && name.startsWith("dev.chimera.attach.GateStub")) {
                    throw new ClassNotFoundException(name);
                }
                return super.loadClass(name, resolve);
            }
        }
    }
}
