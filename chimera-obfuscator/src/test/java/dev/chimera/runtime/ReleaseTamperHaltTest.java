package dev.chimera.runtime;

import dev.chimera.core.ChimeraConfig;
import dev.chimera.core.ChimeraEngine;
import dev.chimera.crypto.Crypto;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * P0-1 "bypass means death": in a <b>release</b> artifact an integrity failure ends the process with
 * {@code halt(4)} instead of silently decaying into decoy values. Dev artifacts keep the historical
 * decay semantics, which is why these cases build with {@code cfg.release = true}.
 *
 * <p>The halt is captured through the test seam ({@code setHaltSinkForTests}), which is inert
 * whenever a release DLL is loaded, so it cannot be used as a bypass in a shipped artifact.</p>
 */
class ReleaseTamperHaltTest {

    @Test
    void tamperedRuntimeClassHaltsReleaseArtifact() throws Exception {
        Path work = Files.createTempDirectory("chimera-release-halt-runtime");
        Path artifact = buildReleaseArtifact(work);
        Path tampered = rewrite(work, artifact, "dev/chimera/runtime/ChimeraTlsPin.class");
        assertEquals(4, triggerInIsolatedLoader(tampered, "fixtures/Lic"),
                "tampered runtime class must halt(4) in a release artifact");
    }

    @Test
    void tamperedIntegrityRecordHaltsReleaseArtifact() throws Exception {
        Path work = Files.createTempDirectory("chimera-release-halt-manifest");
        Path artifact = buildReleaseArtifact(work);
        Path tampered = truncate(work, artifact, "chimera/manifest.mac");
        assertEquals(4, triggerInIsolatedLoader(tampered, "fixtures/Lic"),
                "a replaced/truncated integrity record must halt(4) in a release artifact");
    }

    /** Loads the tampered artifact in an isolated loader and returns the recorded halt code (0 = none). */
    private static int triggerInIsolatedLoader(Path jar, String triggerClass) throws Exception {
        AtomicInteger halted = new AtomicInteger();
        // The test JVM preloads the *dev* DLL; hide it so the isolated runtime resolves the build
        // kind from env.dat exactly like an artifact without the payload (release anchor = native
        // DLL, env marker otherwise). Restored before any assertion runs.
        String nativePath = System.getProperty("chimera.native.auth.path");
        System.clearProperty("chimera.native.auth.path");
        try (URLClassLoader loader = new URLClassLoader(new URL[]{jar.toUri().toURL()},
                ClassLoader.getPlatformClassLoader())) {
            Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true, loader);
            if (nativePath != null) System.setProperty("chimera.native.auth.path", nativePath);
            java.lang.reflect.Method sink = runtime.getDeclaredMethod("setHaltSinkForTests",
                    java.util.function.IntConsumer.class);
            sink.setAccessible(true);
            sink.invoke(null, (java.util.function.IntConsumer) halted::set);
            try {
                Class<?> lic = Class.forName(triggerClass.replace('/', '.'), true, loader);
                lic.getMethod("label").invoke(null);
            } catch (Throwable expected) {
                // the recorded halt throws so no business code runs on a tampered artifact
                System.out.println("[test] trigger threw: " + expected);
            }
            Class<?> switches = Class.forName("dev.chimera.runtime.DebugSwitches", true, loader);
            System.out.println("[test] healthy=" + runtime.getMethod("isKeyHealthy").invoke(null)
                    + " enforced=" + runtime.getMethod("enforceReleasePolicy").invoke(null)
                    + " native=" + runtime.getMethod("isNativeLoaded").invoke(null)
                    + " switch=" + switches.getMethod("state").invoke(null)
                    + " halted=" + halted.get());
        }
        return halted.get();
    }

    private static Path buildReleaseArtifact(Path work) throws Exception {
        Path input = work.resolve("in.jar");
        Files.createDirectories(work);
        try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(input))) {
            for (String name : new String[]{"fixtures/Lic.class", "fixtures/Bonus.class",
                    "fixtures/Hwid.class", "fixtures/Entangled.class"}) {
                try (InputStream in = ReleaseTamperHaltTest.class.getClassLoader()
                        .getResourceAsStream(name)) {
                    assertNotNull(in, "missing fixture " + name);
                    out.putNextEntry(new ZipEntry(name));
                    out.write(in.readAllBytes());
                    out.closeEntry();
                }
            }
        }
        Path output = work.resolve("out.jar");
        ChimeraConfig cfg = new ChimeraConfig();
        cfg.inputJar = input;
        cfg.outputJar = output;
        cfg.keyMaterial = Crypto.sha256("release-halt-key".getBytes(StandardCharsets.UTF_8));
        cfg.resourceKeyMaterial = Crypto.sha256("release-resource-key".getBytes(StandardCharsets.UTF_8));
        cfg.release = true;
        cfg.integrityManifest = true;
        cfg.nativeOutDir = work.resolve("native");
        new ChimeraEngine(cfg).run();
        return output;
    }

    /** Replaces one resource with a truncated copy: an edited/sealed record that cannot authenticate. */
    private static Path truncate(Path work, Path artifact, String entryName) throws Exception {
        Path out = work.resolve("tampered-record.jar");
        try (ZipFile zin = new ZipFile(artifact.toFile());
             ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(out))) {
            var entries = zin.entries();
            boolean found = false;
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                byte[] data;
                try (InputStream in = zin.getInputStream(entry)) {
                    data = in.readAllBytes();
                }
                if (entry.getName().equals(entryName)) {
                    data = java.util.Arrays.copyOf(data, data.length - 1);
                    found = true;
                }
                zos.putNextEntry(new ZipEntry(entry.getName()));
                zos.write(data);
                zos.closeEntry();
            }
            assertEquals(true, found, "entry not found: " + entryName);
        }
        return out;
    }

    /** Flips the last byte of one entry, leaving every other byte intact. */
    private static Path rewrite(Path work, Path artifact, String entryName) throws Exception {
        Path out = work.resolve("tampered.jar");
        try (ZipFile zin = new ZipFile(artifact.toFile());
             ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(out))) {
            var entries = zin.entries();
            boolean found = false;
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                byte[] data;
                try (InputStream in = zin.getInputStream(entry)) {
                    data = in.readAllBytes();
                }
                if (entry.getName().equals(entryName)) {
                    data = data.clone();
                    data[data.length - 1] ^= 0x33;
                    found = true;
                }
                zos.putNextEntry(new ZipEntry(entry.getName()));
                zos.write(data);
                zos.closeEntry();
            }
            assertEquals(true, found, "entry not found: " + entryName);
        }
        return out;
    }
}
