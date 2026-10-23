package dev.chimera;

import dev.chimera.core.ChimeraConfig;
import dev.chimera.core.ChimeraEngine;
import dev.chimera.crypto.Crypto;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Builds a fixture jar, obfuscates it with the engine, then loads the result in an isolated
 * class loader and verifies strings, hidden-class fragments and integrity checks.
 */
public class EndToEndTest {

    private static byte[] fixtureClass(String name) throws Exception {
        try (InputStream in = EndToEndTest.class.getClassLoader().getResourceAsStream(name)) {
            assertNotNull(in, "missing fixture " + name);
            return in.readAllBytes();
        }
    }

    private static Path buildFixtureJar(Path jar) throws Exception {
        Files.createDirectories(jar.getParent());
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(jar))) {
            for (String n : new String[]{"fixtures/Lic.class", "fixtures/Bonus.class", "fixtures/Hwid.class", "fixtures/Entangled.class"}) {
                zos.putNextEntry(new ZipEntry(n));
                zos.write(fixtureClass(n));
                zos.closeEntry();
            }
        }
        return jar;
    }

    private static ChimeraConfig config(Path in, Path out, byte[] key) {
        ChimeraConfig cfg = new ChimeraConfig();
        cfg.inputJar = in;
        cfg.outputJar = out;
        cfg.keyMaterial = key;
        cfg.nativeOutDir = out.resolveSibling("native");
        cfg.integrityManifest = true;
        return cfg;
    }

    @Test
    public void endToEnd() throws Exception {
        Path work = Files.createTempDirectory("chimera-e2e");
        Path in = buildFixtureJar(work.resolve("fixtures.jar"));
        Path out = work.resolve("fixtures-obf.jar");
        byte[] key = Crypto.sha256("test-content-key".getBytes(StandardCharsets.UTF_8));

        var stats = new ChimeraEngine(config(in, out, key)).run();
        assertTrue(stats.stringsEncrypted > 0, "expected encrypted strings");
        assertTrue(stats.methodsFragmented >= 3, "expected >=3 fragments, got " + stats.methodsFragmented);
        assertTrue(stats.methodsNativeStubbed >= 1, "expected 1 native stub");
        assertTrue(stats.honeypotInjected > 0, "expected honeypot branches in small fragments");

        String keyHex = Crypto.hex(key);
        System.setProperty("chimera.contentKey", keyHex);
        try (URLClassLoader cl = new URLClassLoader(new URL[]{out.toUri().toURL()},
                ClassLoader.getPlatformClassLoader())) {
            Class<?> lic = Class.forName("fixtures.Lic", true, cl);
            assertEquals("fixture-secret", lic.getMethod("label").invoke(null));
            assertEquals(Boolean.TRUE, lic.getMethod("check", String.class).invoke(null, "OK-12"));
            assertEquals(81, lic.getMethod("score", int.class, int.class).invoke(null, 2, 3));

            Class<?> bonus = Class.forName("fixtures.Bonus", true, cl);
            Object inst = bonus.getDeclaredConstructor().newInstance();
            assertEquals(52, bonus.getMethod("calc", int.class).invoke(inst, 7));

            Class<?> hwid = Class.forName("fixtures.Hwid", true, cl);
            try {
                hwid.getMethod("hash", String.class).invoke(null, "abc");
                fail("native method should fail without a JNI library");
            } catch (InvocationTargetException e) {
                assertTrue(e.getCause() instanceof UnsatisfiedLinkError);
            }
        }
    }

    @Test
    public void entanglementIsNeutralWithKeyAndCorruptsWithoutKey() throws Exception {
        Path work = Files.createTempDirectory("chimera-e2e-entangle");
        Path in = buildFixtureJar(work.resolve("fixtures.jar"));
        Path out = work.resolve("fixtures-obf.jar");
        byte[] key = Crypto.sha256("test-content-key".getBytes(StandardCharsets.UTF_8));
        var stats = new ChimeraEngine(config(in, out, key)).run();
        assertTrue(stats.entangledMethods >= 3, "expected entangled methods, got " + stats.entangledMethods);

        System.setProperty("chimera.contentKey", Crypto.hex(key));
        try (URLClassLoader cl = new URLClassLoader(new URL[]{out.toUri().toURL()},
                ClassLoader.getPlatformClassLoader())) {
            Class<?> e = Class.forName("fixtures.Entangled", true, cl);
            assertEquals(47, e.getMethod("damage", int.class, int.class).invoke(null, 2, 3));
            assertEquals(72L, e.getMethod("gold", long.class).invoke(null, 5L));
            assertEquals(1.75d, ((Double) e.getMethod("ratio", int.class, int.class).invoke(null, 2, 3)).doubleValue(), 1e-9);
        }

        System.clearProperty("chimera.contentKey");
        try (URLClassLoader cl = new URLClassLoader(new URL[]{out.toUri().toURL()},
                ClassLoader.getPlatformClassLoader())) {
            Class<?> e = Class.forName("fixtures.Entangled", true, cl);
            Object damage = e.getMethod("damage", int.class, int.class).invoke(null, 2, 3);
            assertNotEquals(47, ((Integer) damage).intValue(), "poisoned damage should be corrupted");
            Object gold = e.getMethod("gold", long.class).invoke(null, 5L);
            assertNotEquals(72L, ((Long) gold).longValue(), "poisoned gold should be corrupted");
            Object ratio = e.getMethod("ratio", int.class, int.class).invoke(null, 2, 3);
            assertTrue(Double.isNaN(((Double) ratio).doubleValue()), "poisoned ratio should be NaN");
        }
    }

    @Test
    public void nonceRotationInvalidatesOldStampAndRecoversOnRefresh() throws Exception {
        Path work = Files.createTempDirectory("chimera-e2e-nonce");
        Path in = buildFixtureJar(work.resolve("fixtures.jar"));
        Path out = work.resolve("fixtures-obf.jar");
        byte[] key = Crypto.sha256("test-content-key".getBytes(StandardCharsets.UTF_8));
        new ChimeraEngine(config(in, out, key)).run();
        System.setProperty("chimera.contentKey", Crypto.hex(key));

        try (URLClassLoader cl = new URLClassLoader(new URL[]{out.toUri().toURL()},
                ClassLoader.getPlatformClassLoader())) {
            Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true, cl);
            var nonce = runtime.getMethod("updateServerNonce", long.class);
            var stamp = runtime.getMethod("sessionStamp");
            var verify = runtime.getMethod("verifySessionStamp", long.class);
            var healthy = runtime.getMethod("isKeyHealthy");

            nonce.invoke(null, 111L);
            long oldStamp = (Long) stamp.invoke(null);
            assertEquals(oldStamp, (Long) stamp.invoke(null), "stamp must be stable within a nonce");

            nonce.invoke(null, 222L);
            long newStamp = (Long) stamp.invoke(null);
            assertNotEquals(oldStamp, newStamp, "stamp must rotate with the nonce");

            verify.invoke(null, oldStamp);
            assertEquals(Boolean.FALSE, healthy.invoke(null),
                    "verifying a stale stamp must poison the runtime");

            nonce.invoke(null, 333L);
            assertEquals(Boolean.TRUE, healthy.invoke(null),
                    "a fresh nonce with a valid key must recover the session");
        }
    }

    @Test
    public void timingWindowPoisonsOnlyAfterThreeConsecutiveSlowBootstraps() throws Exception {
        Path work = Files.createTempDirectory("chimera-e2e-timing");
        Path in = buildFixtureJar(work.resolve("fixtures.jar"));
        Path out = work.resolve("fixtures-obf.jar");
        byte[] key = Crypto.sha256("test-content-key".getBytes(StandardCharsets.UTF_8));
        new ChimeraEngine(config(in, out, key)).run();
        System.setProperty("chimera.contentKey", Crypto.hex(key));

        try (URLClassLoader cl = new URLClassLoader(new URL[]{out.toUri().toURL()},
                ClassLoader.getPlatformClassLoader())) {
            Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true, cl);
            java.util.concurrent.atomic.AtomicLong clock = new java.util.concurrent.atomic.AtomicLong();
            // 200 ms per bootstrap: above the 100 ms window threshold, below "one hiccup = poison".
            java.util.function.LongSupplier slow = () -> clock.addAndGet(200_000_000L);
            runtime.getMethod("resetTimingSuspicion").invoke(null);
            runtime.getMethod("setTimingSource", java.util.function.LongSupplier.class).invoke(null, slow);

            Class<?> bonus = Class.forName("fixtures.Bonus", true, cl);
            Object instance = bonus.getDeclaredConstructor().newInstance();
            assertEquals(52, ((Integer) bonus.getMethod("calc", int.class).invoke(instance, 7)).intValue());
            assertEquals(Boolean.TRUE, runtime.getMethod("isKeyHealthy").invoke(null),
                    "one slow bootstrap must not poison (window requires 3 consecutive)");
            assertEquals(1, ((Integer) runtime.getMethod("timingSuspicionCount").invoke(null)).intValue());
            long wiped = (Long) runtime.getMethod("wipeCount").invoke(null);
            assertTrue(wiped >= 1, "decrypted class bytes must be wiped at least once");
            assertEquals(Boolean.TRUE, runtime.getMethod("lastWipeZeroed").invoke(null),
                    "M3: the byte[] passed to defineHiddenClass must be zeroed after define");

            Class<?> lic = Class.forName("fixtures.Lic", true, cl);
            assertEquals(Boolean.TRUE, lic.getMethod("check", String.class).invoke(null, "OK-12"),
                    "second slow sample is still below the 3-consecutive window");
            assertEquals(Boolean.TRUE, runtime.getMethod("isKeyHealthy").invoke(null));
            assertEquals(81, ((Integer) lic.getMethod("score", int.class, int.class).invoke(null, 2, 3)).intValue());
            assertEquals(Boolean.FALSE, runtime.getMethod("isKeyHealthy").invoke(null),
                    "third consecutive slow bootstrap must poison the session");
            Object agentSource = runtime.getMethod("timingAgentSignalSource").invoke(null);
            assertEquals(3, ((Integer) runtime.getMethod("requiredTimingSuspicions").invoke(null)).intValue(),
                    "agent signal source in this JVM: " + agentSource);
            assertEquals(100_000_000L, ((Long) runtime.getMethod("timingWindowThresholdNanos").invoke(null)).longValue());

            // M2: poisoned state corrupts values (negative int / NaN double), never throws.
            Class<?> entangled = Class.forName("fixtures.Entangled", true, cl);
            Object damage = entangled.getMethod("damage", int.class, int.class).invoke(null, 2, 3);
            assertTrue(((Integer) damage).intValue() < 0 || ((Integer) damage).intValue() != 47);
            Object ratio = entangled.getMethod("ratio", int.class, int.class).invoke(null, 2, 3);
            assertTrue(Double.isNaN(((Double) ratio).doubleValue()));

            runtime.getMethod("resetTimingSource").invoke(null);
        } finally {
            System.clearProperty("chimera.contentKey");
        }
    }

    @Test
    public void coreDefencesSurviveNewFeatures() throws Exception {
        Path work = Files.createTempDirectory("chimera-e2e-core");
        Path in = buildFixtureJar(work.resolve("fixtures.jar"));
        Path out = work.resolve("fixtures-obf.jar");
        byte[] key = Crypto.sha256("test-content-key".getBytes(StandardCharsets.UTF_8));
        var stats = new ChimeraEngine(config(in, out, key)).run();
        System.setProperty("chimera.contentKey", Crypto.hex(key));

        // M6: decoy tokens + dead-loop honeypot stay in the injected runtime.
        byte[] runtimeBytes;
        try (ZipFile zip = new ZipFile(out.toFile());
             InputStream stream = zip.getInputStream(zip.getEntry("dev/chimera/runtime/ChimeraRuntime.class"))) {
            runtimeBytes = stream.readAllBytes();
        }
        String runtimeText = new String(runtimeBytes, StandardCharsets.ISO_8859_1);
        assertTrue(runtimeText.contains("frida_bypass"), "M6 decoy token must survive in the runtime");
        assertTrue(runtimeText.contains("honeypotTrap"), "M6 dead-loop honeypot must be referenceable");
        assertTrue(stats.honeypotInjected > 0, "honeypot branches must be injected into small fragments");

        try (URLClassLoader cl = new URLClassLoader(new URL[]{out.toUri().toURL()},
                ClassLoader.getPlatformClassLoader())) {
            Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true, cl);
            Class<?> lic = Class.forName("fixtures.Lic", true, cl);
            // First fragmented call triggers the hidden-class bootstrap, then M3 wipe is observable.
            assertEquals(Boolean.TRUE, lic.getMethod("check", String.class).invoke(null, "OK-12"));
            assertEquals("fixture-secret", lic.getMethod("label").invoke(null));
            assertEquals(Boolean.TRUE, runtime.getMethod("isKeyHealthy").invoke(null));

            // M3: hidden-class byte[] wiped and verified zero.
            assertEquals(Boolean.TRUE, runtime.getMethod("lastWipeZeroed").invoke(null));
            assertTrue(((Long) runtime.getMethod("wipeCount").invoke(null)) >= 1L);

            // M2: nonce rollback poisons arithmetic (negative int, NaN double), no exception.
            var stamp = runtime.getMethod("sessionStamp");
            var nonce = runtime.getMethod("updateServerNonce", long.class);
            var verify = runtime.getMethod("verifySessionStamp", long.class);
            Class<?> entangled = Class.forName("fixtures.Entangled", true, cl);
            assertEquals(47, ((Integer) entangled.getMethod("damage", int.class, int.class)
                    .invoke(null, 2, 3)).intValue());
            long oldStamp = (Long) stamp.invoke(null);
            nonce.invoke(null, 777L);
            verify.invoke(null, oldStamp);
            assertEquals(Boolean.FALSE, runtime.getMethod("isKeyHealthy").invoke(null));
            Object damaged = entangled.getMethod("damage", int.class, int.class).invoke(null, 2, 3);
            assertTrue(((Integer) damaged).intValue() < 0,
                    "M2 poisoned int value must be negative, got " + damaged);
            Object brokenRatio = entangled.getMethod("ratio", int.class, int.class).invoke(null, 2, 3);
            assertTrue(Double.isNaN(((Double) brokenRatio).doubleValue()));

            // @ChimeraPreGameCheck failure mode: returning false without a dialog/exception, while
            // business values remain degraded (negative ints / NaN doubles).
            Object preGame = runtime.getMethod("preGameCheck", String.class, String.class, String.class)
                    .invoke(null, "demo", "wrong", "hwid");
            assertEquals(Boolean.FALSE, preGame, "pre-game check must fail closed");
            Object afterPreGame = entangled.getMethod("damage", int.class, int.class).invoke(null, 2, 3);
            assertTrue(((Integer) afterPreGame).intValue() < 0);
        } finally {
            System.clearProperty("chimera.contentKey");
        }
    }

    @Test
    public void tamperedRuntimeClassIsDetectedBySelfHash() throws Exception {
        Path work = Files.createTempDirectory("chimera-e2e-runtime-hash");
        Path in = buildFixtureJar(work.resolve("fixtures.jar"));
        Path out = work.resolve("fixtures-obf.jar");
        byte[] key = Crypto.sha256("test-content-key".getBytes(StandardCharsets.UTF_8));
        new ChimeraEngine(config(in, out, key)).run();

        Path tampered = work.resolve("runtime-tampered.jar");
        try (ZipFile zin = new ZipFile(out.toFile());
             ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(tampered))) {
            var en = zin.entries();
            while (en.hasMoreElements()) {
                ZipEntry entry = en.nextElement();
                byte[] data;
                try (InputStream is = zin.getInputStream(entry)) { data = is.readAllBytes(); }
                if (entry.getName().equals("dev/chimera/runtime/ChimeraTlsPin.class")) {
                    data = data.clone();
                    data[data.length - 1] ^= 0x33;
                }
                zos.putNextEntry(new ZipEntry(entry.getName()));
                zos.write(data);
                zos.closeEntry();
            }
        }

        System.setProperty("chimera.contentKey", Crypto.hex(key));
        try (URLClassLoader cl = new URLClassLoader(new URL[]{tampered.toUri().toURL()},
                ClassLoader.getPlatformClassLoader())) {
            Class<?> lic = Class.forName("fixtures.Lic", true, cl);
            assertNotEquals("fixture-secret", lic.getMethod("label").invoke(null),
                    "tampered runtime class must fail closed and return decoys");
            Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true, cl);
            assertEquals(Boolean.FALSE, runtime.getMethod("isKeyHealthy").invoke(null));
        } finally {
            System.clearProperty("chimera.contentKey");
        }
    }

    @Test
    public void tamperedClassIsDetected() throws Exception {
        Path work = Files.createTempDirectory("chimera-e2e-tamper");
        Path in = buildFixtureJar(work.resolve("fixtures.jar"));
        Path out = work.resolve("fixtures-obf.jar");
        byte[] key = Crypto.sha256("test-content-key".getBytes(StandardCharsets.UTF_8));
        new ChimeraEngine(config(in, out, key)).run();

        Path tampered = work.resolve("tampered.jar");
        try (ZipFile zin = new ZipFile(out.toFile());
             ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(tampered))) {
            var en = zin.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
                byte[] data;
                try (InputStream is = zin.getInputStream(e)) { data = is.readAllBytes(); }
                if (e.getName().equals("fixtures/Bonus.class")) {
                    data = data.clone();
                    data[data.length - 1] ^= 0x55;
                }
                zos.putNextEntry(new ZipEntry(e.getName()));
                zos.write(data);
                zos.closeEntry();
            }
        }

        System.setProperty("chimera.contentKey", Crypto.hex(key));
        try (URLClassLoader cl = new URLClassLoader(new URL[]{tampered.toUri().toURL()},
                ClassLoader.getPlatformClassLoader())) {
            Class<?> lic = Class.forName("fixtures.Lic", true, cl);
            // M2: integrity failure must not surface as a catchable authorization exception.
            String label = (String) lic.getMethod("label").invoke(null);
            assertNotEquals("fixture-secret", label, "tampered jar must return a decoy string");
            Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true, cl);
            assertEquals(Boolean.FALSE, runtime.getMethod("isKeyHealthy").invoke(null),
                    "runtime should be poisoned after integrity failure");
        }
    }
}
