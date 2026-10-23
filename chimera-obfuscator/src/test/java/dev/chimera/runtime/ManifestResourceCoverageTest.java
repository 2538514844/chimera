package dev.chimera.runtime;

import dev.chimera.core.ChimeraConfig;
import dev.chimera.core.ChimeraEngine;
import dev.chimera.crypto.Crypto;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * #9 (audit 2026-10-22): {@code chimera/manifest.dat} must cover <b>every</b> {@code chimera/**}
 * resource, and a rewritten / added one must halt a release artifact with exit code 4.
 *
 * <p>Before the fix the manifest only listed classes, so {@code auth.dat}, {@code env.dat},
 * {@code strings.dat}, {@code attach/agent.jar} and the native payload had no integrity coverage at
 * all: deleting one {@code pubkey=} line from {@code auth.dat} disabled the gate without a trace.</p>
 */
class ManifestResourceCoverageTest {

    @Test
    void manifestIsChm2AndListsEveryChimeraResource() throws Exception {
        Path work = Files.createTempDirectory("chimera-manifest-coverage");
        Path artifact = buildReleaseArtifact(work);
        try (ZipFile zip = new ZipFile(artifact.toFile())) {
            ZipEntry manifestEntry = zip.getEntry("chimera/manifest.dat");
            assertNotNull(manifestEntry, "manifest.dat must be present");
            String manifest = new String(zip.getInputStream(manifestEntry).readAllBytes(),
                    StandardCharsets.UTF_8);
            assertTrue(manifest.startsWith("CHM2\n"),
                    "full-coverage manifests carry the CHM2 header");
            // Every chimera/** entry in the artifact must be listed, except the three records that
            // cannot list themselves and the per-chunk AES-GCM payloads (they carry their own
            // sealed digests).
            var entries = zip.entries();
            int covered = 0;
            while (entries.hasMoreElements()) {
                String name = entries.nextElement().getName();
                if (!name.startsWith("chimera/")) continue;
                if (name.equals("chimera/manifest.dat") || name.equals("chimera/manifest.mac")
                        || name.equals("chimera/manifest.hmac")) {
                    continue;
                }
                if (name.startsWith("chimera/chunks/") || name.startsWith("chimera/classes/")) {
                    continue;
                }
                assertTrue(manifest.contains("  " + name + "\n"),
                        "manifest must cover " + name);
                covered++;
            }
            assertTrue(covered >= 5, "expected several covered resources, got " + covered);
            // The audit's headline gap: auth.dat was completely uncovered.
            assertTrue(manifest.contains("  chimera/auth.dat\n"), "auth.dat must be covered");
            assertTrue(manifest.contains("  chimera/env.dat\n"), "env.dat must be covered");
            assertFalse(manifest.contains("  chimera/manifest.dat\n"),
                    "the manifest must not list itself");
            // C (2026-10-22): the runtime classes are plaintext (they must load before the key
            // exists) and are therefore the only replaceable part of the artifact. They used to be
            // dropped in bulk because the filter asked classEncryptKeep.keep() with the RENAMED name
            // and got null back - so the manifest listed 157 chimera/** entries and zero classes.
            // This assertion is what would have caught it.
            int runtimeClasses = 0;
            var classEntries = zip.entries();
            while (classEntries.hasMoreElements()) {
                String name = classEntries.nextElement().getName();
                if (!name.startsWith("dev/chimera/") || !name.endsWith(".class")) continue;
                assertTrue(manifest.contains("  " + name + "\n"),
                        "manifest must cover runtime class " + name);
                runtimeClasses++;
            }
            assertTrue(runtimeClasses >= 5,
                    "expected the runtime classes in the artifact, got " + runtimeClasses);
        }
        assertEquals(0, triggerInIsolatedLoader(artifact),
                "an untouched artifact must not halt");
    }

    @Test
    void tamperedAuthDatHaltsReleaseArtifact() throws Exception {
        Path work = Files.createTempDirectory("chimera-manifest-auth");
        Path artifact = buildReleaseArtifact(work);
        // The exact attack from the audit: drop the pubkey= line so the gate cannot verify anything.
        Path tampered = rewrite(work.resolve("auth-tampered.jar"), artifact, "chimera/auth.dat",
                data -> new String(data, StandardCharsets.UTF_8)
                        .replaceAll("(?m)^pubkey=.*\\R", "").getBytes(StandardCharsets.UTF_8));
        assertEquals(4, triggerInIsolatedLoader(tampered),
                "a rewritten auth.dat must halt(4) in a release artifact");
    }

    @Test
    void unlistedChimeraResourceHaltsReleaseArtifact() throws Exception {
        Path work = Files.createTempDirectory("chimera-manifest-extra");
        Path artifact = buildReleaseArtifact(work);
        // Append an entry the build never recorded.
        Path withExtra = work.resolve("extra-entry.jar");
        try (ZipFile zin = new ZipFile(artifact.toFile());
             ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(withExtra))) {
            var entries = zin.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                byte[] data;
                try (InputStream in = zin.getInputStream(entry)) {
                    data = in.readAllBytes();
                }
                zos.putNextEntry(new ZipEntry(entry.getName()));
                zos.write(data);
                zos.closeEntry();
            }
            zos.putNextEntry(new ZipEntry("chimera/injected.dat"));
            zos.write("injected".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }
        assertEquals(4, triggerInIsolatedLoader(withExtra),
                "an unlisted chimera/** resource must halt(4) in a release artifact");
    }

    /** Loads the artifact in an isolated loader and returns the recorded halt code (0 = none). */
    private static int triggerInIsolatedLoader(Path jar) throws Exception {
        AtomicInteger halted = new AtomicInteger();
        String nativePath = System.getProperty("chimera.native.auth.path");
        System.clearProperty("chimera.native.auth.path");
        try (java.net.URLClassLoader loader = new java.net.URLClassLoader(
                new java.net.URL[]{jar.toUri().toURL()}, ClassLoader.getPlatformClassLoader())) {
            Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true, loader);
            if (nativePath != null) System.setProperty("chimera.native.auth.path", nativePath);
            java.lang.reflect.Method sink = runtime.getDeclaredMethod("setHaltSinkForTests",
                    java.util.function.IntConsumer.class);
            sink.setAccessible(true);
            sink.invoke(null, (java.util.function.IntConsumer) halted::set);
            try {
                Class<?> lic = Class.forName("fixtures.Lic", true, loader);
                lic.getMethod("label").invoke(null);
            } catch (Throwable expected) {
                // the recorded halt throws so no business code runs on a tampered artifact
                System.out.println("[test] trigger threw: " + expected);
            }
        }
        return halted.get();
    }

    private static Path buildReleaseArtifact(Path work) throws Exception {
        Path input = work.resolve("in.jar");
        Files.createDirectories(work);
        try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(input))) {
            for (String name : new String[]{"fixtures/Lic.class", "fixtures/Bonus.class",
                    "fixtures/Hwid.class", "fixtures/Entangled.class"}) {
                try (InputStream in = ManifestResourceCoverageTest.class.getClassLoader()
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
        cfg.keyMaterial = Crypto.sha256("manifest-coverage-key".getBytes(StandardCharsets.UTF_8));
        cfg.resourceKeyMaterial =
                Crypto.sha256("manifest-coverage-resource".getBytes(StandardCharsets.UTF_8));
        cfg.release = true;
        cfg.integrityManifest = true;
        // auth.dat only exists when the build carries a server + key.
        cfg.authServer = "https://licence.example.invalid";
        cfg.authPubkey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        cfg.nativeOutDir = work.resolve("native");
        new ChimeraEngine(cfg).run();
        return output;
    }

    /** Rewrites one entry through {@code transform}, keeping every other byte intact. */
    private static Path rewrite(Path out, Path artifact, String entryName,
                                java.util.function.UnaryOperator<byte[]> transform)
            throws Exception {
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
                    data = transform.apply(data);
                    found = true;
                }
                zos.putNextEntry(new ZipEntry(entry.getName()));
                zos.write(data);
                zos.closeEntry();
            }
            assertTrue(found, "entry not found: " + entryName);
        }
        return out;
    }
}
