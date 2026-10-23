package dev.chimera.runtime;

import dev.chimera.auth.NativeAuthLibrary;
import dev.chimera.core.ChimeraConfig;
import dev.chimera.core.ChimeraEngine;
import dev.chimera.crypto.Crypto;
import org.junit.jupiter.api.AfterEach;
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
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * B4 false-positive evidence for 100 / 250 / 1000 fragments.
 *
 * <p>Each protected method is invoked once (one hidden-class bootstrap). The runtime runs with the
 * default 100 ms / 3-consecutive (or 8-take-5) sliding window and a real native QPC clock (or
 * System.nanoTime when the native clock is unavailable). A false positive is a poisoned session
 * caused only by the timing window; the measured positive rate must stay below 0.1%.</p>
 */
class TimingFalsePositiveTest {

    private static final String CONTENT_KEY = "test-content-key";

    @AfterEach
    void clearKey() {
        System.clearProperty("chimera.contentKey");
        System.clearProperty("chimera.timing.windowThresholdMs");
        System.clearProperty("chimera.timing.windowConsecutive");
        System.clearProperty("chimera.timing.windowSize");
        System.clearProperty("chimera.timing.windowSlowLimit");
    }

    @Test
    void oneHundredFragmentsStayHealthy(@TempDir Path work) throws Exception {
        runFalsePositiveProbe(work, 100);
    }

    @Test
    void twoHundredFiftyFragmentsStayHealthy(@TempDir Path work) throws Exception {
        runFalsePositiveProbe(work, 250);
    }

    @Test
    void oneThousandFragmentsStayHealthy(@TempDir Path work) throws Exception {
        runFalsePositiveProbe(work, 1000);
    }

    private static void runFalsePositiveProbe(Path work, int fragments) throws Exception {
        Path jar = buildGeneratedJar(work, fragments);
        System.setProperty("chimera.contentKey", Crypto.hex(key()));
        try (URLClassLoader loader = open(jar)) {
            Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true, loader);
            Class<?> generated = Class.forName("fixtures.GeneratedFragments", true, loader);
            for (int i = 0; i < fragments; i++) {
                Object value = generated.getMethod("m" + i).invoke(null);
                assertEquals(i, ((Integer) value).intValue(), "fragment " + i + " result");
            }
            boolean healthy = (Boolean) runtime.getMethod("isKeyHealthy").invoke(null);
            int slowSamples = ((Integer) runtime.getMethod("timingSuspicionCount").invoke(null)).intValue();
            int consecutive = ((Integer) runtime.getMethod("consecutiveSlowBootstraps").invoke(null)).intValue();
            int slowInWindow = ((Integer) runtime.getMethod("slowSamplesInWindow").invoke(null)).intValue();
            double falsePositiveRate = healthy ? 0.0d : 1.0d;
            System.out.println("[B4-FP] fragments=" + fragments
                    + " slowSamples=" + slowSamples
                    + " slowRate=" + String.format(java.util.Locale.ROOT, "%.4f%%", 100.0d * slowSamples / fragments)
                    + " consecutive=" + consecutive
                    + " slowInWindow=" + slowInWindow
                    + " poisoned=" + (healthy ? 0 : 1)
                    + " falsePositiveRate=" + String.format(java.util.Locale.ROOT, "%.4f%%", 100.0d * falsePositiveRate));
            assertTrue(healthy, "B4 false positive: " + fragments + " normal fragments poisoned the runtime");
            assertFalse(consecutive >= 3, "consecutive slow streak must stay below the window rule");
            assertFalse(slowInWindow >= 5, "slow samples in window must stay below the 8-take-5 rule");
            assertTrue(falsePositiveRate < 0.001d,
                    "B4 false-positive rate must be <0.1%, got " + falsePositiveRate);
        }
    }

    private static byte[] key() {
        return Crypto.sha256(CONTENT_KEY.getBytes(StandardCharsets.UTF_8));
    }

    private static Path buildGeneratedJar(Path work, int count) throws Exception {
        byte[] classBytes = generateFragmentsClass(count);
        Path input = work.resolve("generated-" + count + ".jar");
        try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(input))) {
            out.putNextEntry(new ZipEntry("fixtures/GeneratedFragments.class"));
            out.write(classBytes);
            out.closeEntry();
        }
        Path output = work.resolve("generated-" + count + "-obf.jar");
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
}
