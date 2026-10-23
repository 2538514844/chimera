package dev.chimera.runtime;

import dev.chimera.auth.NativeAuthLibrary;
import dev.chimera.core.ChimeraConfig;
import dev.chimera.core.ChimeraEngine;
import dev.chimera.crypto.Crypto;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.LongSupplier;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * B4 sliding-window timing semantics:
 * <ul>
 *   <li>sample = one hidden-class fragment bootstrap;</li>
 *   <li>slow = elapsed &gt; 100 ms on the native QPC clock (injected source in tests);</li>
 *   <li>poison when the last 8 samples contain &gt;=5 slow samples OR &gt;=3 slow samples in a row;</li>
 *   <li>a detected Java agent/JDWP/Frida lowers the requirement to one slow sample;</li>
 *   <li>one isolated slow sample must never poison a legitimate player.</li>
 * </ul>
 *
 * <p>The old ThreadMXBean 10 ms CPU threshold is gone. B5 agent detection still feeds the
 * threshold through {@link ChimeraRuntime#timingAgentDetected()}.</p>
 */
class M5WallClockFridaTest {

    private static final String CONTENT_KEY = "test-content-key";
    private static final long SLOW = 200_000_000L; // 200 ms > 100 ms threshold
    private static final long FAST = 10_000_000L;  // 10 ms

    @BeforeEach
    void resetDirectRuntime() {
        ChimeraRuntime.resetAgentSignalsForTests();
        ChimeraRuntime.resetTimingSuspicion();
    }

    @AfterEach
    void cleanup() {
        System.clearProperty("chimera.contentKey");
        System.clearProperty("chimera.timing.windowThresholdMs");
        System.clearProperty("chimera.timing.windowConsecutive");
        System.clearProperty("chimera.timing.windowSize");
        System.clearProperty("chimera.timing.windowSlowLimit");
        ChimeraRuntime.resetAgentSignalsForTests();
        ChimeraRuntime.resetTimingSuspicion();
    }

    @Test
    void oneSlowBootstrapDoesNotPoison(@TempDir Path work) throws Exception {
        Path jar = buildGeneratedJar(work, 4);
        System.setProperty("chimera.contentKey", Crypto.hex(key()));
        try (URLClassLoader loader = open(jar)) {
            Class<?> runtime = runtime(loader);
            Class<?> fragments = fragments(loader);
            runtime.getMethod("setTimingSource", LongSupplier.class).invoke(null, clock(SLOW));

            assertEquals(0, invoke(fragments, 0));
            assertEquals(Boolean.TRUE, runtime.getMethod("isKeyHealthy").invoke(null),
                    "one slow sample must not poison a legitimate player");
            assertEquals(1, ((Integer) runtime.getMethod("timingSuspicionCount").invoke(null)).intValue());
            assertEquals(1, ((Integer) runtime.getMethod("consecutiveSlowBootstraps").invoke(null)).intValue());
        }
    }

    @Test
    void threeConsecutiveSlowBootstrapsPoison(@TempDir Path work) throws Exception {
        Path jar = buildGeneratedJar(work, 4);
        System.setProperty("chimera.contentKey", Crypto.hex(key()));
        try (URLClassLoader loader = open(jar)) {
            Class<?> runtime = runtime(loader);
            Class<?> fragments = fragments(loader);
            runtime.getMethod("setTimingSource", LongSupplier.class).invoke(null, clock(SLOW, SLOW, SLOW));

            invoke(fragments, 0);
            invoke(fragments, 1);
            assertEquals(Boolean.TRUE, runtime.getMethod("isKeyHealthy").invoke(null));
            invoke(fragments, 2);
            assertEquals(Boolean.FALSE, runtime.getMethod("isKeyHealthy").invoke(null),
                    "three consecutive slow bootstraps must poison");
            assertEquals(3, ((Integer) runtime.getMethod("timingSuspicionCount").invoke(null)).intValue());
        }
    }

    @Test
    void fiveSlowSamplesInEightPoisonWithoutThreeConsecutive(@TempDir Path work) throws Exception {
        Path jar = buildGeneratedJar(work, 8);
        System.setProperty("chimera.contentKey", Crypto.hex(key()));
        try (URLClassLoader loader = open(jar)) {
            Class<?> runtime = runtime(loader);
            Class<?> fragments = fragments(loader);
            // slow, fast, slow, fast, slow, fast, slow, slow => 5/8 slow, max streak 2
            runtime.getMethod("setTimingSource", LongSupplier.class).invoke(
                    null, clock(SLOW, FAST, SLOW, FAST, SLOW, FAST, SLOW, SLOW));

            for (int i = 0; i < 7; i++) {
                invoke(fragments, i);
                assertEquals(Boolean.TRUE, runtime.getMethod("isKeyHealthy").invoke(null),
                        "must stay healthy before the 8th sample, i=" + i);
            }
            assertEquals(1, ((Integer) runtime.getMethod("consecutiveSlowBootstraps").invoke(null)).intValue());
            invoke(fragments, 7);
            assertEquals(Boolean.FALSE, runtime.getMethod("isKeyHealthy").invoke(null),
                    "5 slow samples in the last 8 must poison without 3 consecutive");
        }
    }

    @Test
    void fastBootstrapResetsTheConsecutiveStreak(@TempDir Path work) throws Exception {
        Path jar = buildGeneratedJar(work, 8);
        System.setProperty("chimera.contentKey", Crypto.hex(key()));
        try (URLClassLoader loader = open(jar)) {
            Class<?> runtime = runtime(loader);
            Class<?> fragments = fragments(loader);
            runtime.getMethod("setTimingSource", LongSupplier.class).invoke(
                    null, clock(SLOW, SLOW, FAST, SLOW, SLOW));

            for (int i = 0; i < 5; i++) invoke(fragments, i);
            assertEquals(Boolean.TRUE, runtime.getMethod("isKeyHealthy").invoke(null),
                    "a fast sample must reset the consecutive streak");
            assertEquals(2, ((Integer) runtime.getMethod("consecutiveSlowBootstraps").invoke(null)).intValue());
            assertEquals(4, ((Integer) runtime.getMethod("timingSuspicionCount").invoke(null)).intValue());
        }
    }

    @Test
    void fridaThreadLowersRequirementToOneSlowSample(@TempDir Path work) throws Exception {
        Thread frida = new Thread(() -> {
            try {
                Thread.sleep(60_000L);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }, "gum-js-loop");
        frida.setDaemon(true);
        frida.start();
        try {
            Path jar = buildGeneratedJar(work, 4);
            System.setProperty("chimera.contentKey", Crypto.hex(key()));
            try (URLClassLoader loader = open(jar)) {
                Class<?> runtime = runtime(loader);
                Class<?> fragments = fragments(loader);
                runtime.getMethod("resetAgentSignalsForTests").invoke(null);
                assertTrue((Boolean) runtime.getMethod("timingAgentDetected").invoke(null));
                assertEquals(1, ((Integer) runtime.getMethod("requiredTimingSuspicions").invoke(null)).intValue());
                runtime.getMethod("setTimingSource", LongSupplier.class).invoke(null, clock(SLOW));
                invoke(fragments, 0);
                assertEquals(Boolean.FALSE, runtime.getMethod("isKeyHealthy").invoke(null),
                        "with a detected agent one slow sample is enough");
            }
        } finally {
            frida.interrupt();
            frida.join(2_000L);
            ChimeraRuntime.resetAgentSignalsForTests();
        }
    }

    @Test
    void fridaThreadNameIsAnAgentSignalAndDefaultWindowIsThree() {
        Thread frida = new Thread(() -> {
            try {
                Thread.sleep(60_000L);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }, "gum-js-loop");
        frida.setDaemon(true);
        frida.start();
        try {
            ChimeraRuntime.resetAgentSignalsForTests();
            assertTrue(ChimeraRuntime.timingAgentDetected());
            assertEquals(1, ChimeraRuntime.requiredTimingSuspicions());
            String source = ChimeraRuntime.timingAgentSignalSource();
            assertNotNull(source);
            assertTrue(source.startsWith("thread:"), "unexpected source: " + source);
        } finally {
            frida.interrupt();
            try {
                frida.join(2_000L);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
            ChimeraRuntime.resetAgentSignalsForTests();
        }

        Assumptions.assumeFalse(ChimeraRuntime.timingAgentDetected(),
                "test JVM already instrumented; default-window check skipped");
        assertEquals(3, ChimeraRuntime.requiredTimingSuspicions());
        assertEquals(100_000_000L, ChimeraRuntime.timingWindowThresholdNanos());
    }

    // ------------------------------------------------------------------ helpers

    private static byte[] key() {
        return Crypto.sha256(CONTENT_KEY.getBytes(StandardCharsets.UTF_8));
    }

    private static Path buildGeneratedJar(Path work, int count) throws Exception {
        byte[] classBytes = generateFragmentsClass(count);
        Path input = work.resolve("generated.jar");
        try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(input))) {
            out.putNextEntry(new ZipEntry("fixtures/GeneratedFragments.class"));
            out.write(classBytes);
            out.closeEntry();
        }
        Path output = work.resolve("generated-obf.jar");
        ChimeraConfig config = new ChimeraConfig();
        config.inputJar = input;
        config.outputJar = output;
        config.keyMaterial = key();
        config.nativeOutDir = work.resolve("native");
        config.integrityManifest = true;
        new ChimeraEngine(config).run();
        return output;
    }

    private static byte[] generateFragmentsClass(int count) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER,
                "fixtures/GeneratedFragments", null, "java/lang/Object", null);
        for (int i = 0; i < count; i++) {
            MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                    "m" + i, "()I", null, null);
            method.visitAnnotation("Ldev/chimera/annotations/ChimeraProtected;", false).visitEnd();
            method.visitCode();
            method.visitLdcInsn(Integer.valueOf(i));
            method.visitInsn(Opcodes.IRETURN);
            method.visitMaxs(1, 0);
            method.visitEnd();
        }
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static URLClassLoader open(Path jar) throws Exception {
        NativeAuthLibrary.prepareIsolatedCopy();
        return new URLClassLoader(new URL[]{jar.toUri().toURL()}, ClassLoader.getPlatformClassLoader());
    }

    private static Class<?> runtime(URLClassLoader loader) throws Exception {
        return Class.forName("dev.chimera.runtime.ChimeraRuntime", true, loader);
    }

    private static Class<?> fragments(URLClassLoader loader) throws Exception {
        return Class.forName("fixtures.GeneratedFragments", true, loader);
    }

    private static int invoke(Class<?> fragments, int index) throws Exception {
        return ((Integer) fragments.getMethod("m" + index).invoke(null)).intValue();
    }

    /** Deterministic monotonic clock: each bootstrap consumes two reads and sees its scripted delta. */
    private static LongSupplier clock(long... sampleDurationsNanos) {
        long[] ticks = new long[sampleDurationsNanos.length * 2];
        long now = 0L;
        for (int i = 0; i < sampleDurationsNanos.length; i++) {
            ticks[i * 2] = now;
            now += sampleDurationsNanos[i];
            ticks[i * 2 + 1] = now;
        }
        AtomicInteger index = new AtomicInteger();
        return () -> ticks[Math.min(index.getAndIncrement(), ticks.length - 1)];
    }
}
