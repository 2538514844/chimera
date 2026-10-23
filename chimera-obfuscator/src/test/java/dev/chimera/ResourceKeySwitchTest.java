package dev.chimera;

import dev.chimera.auth.MockLicenseServer;
import dev.chimera.auth.NativeAuthLibrary;
import dev.chimera.core.ChimeraConfig;
import dev.chimera.core.ChimeraEngine;
import dev.chimera.crypto.Crypto;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.lang.reflect.Field;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * KI-28: build-time ResourceKey switch.
 *
 * <p>Covers the user-facing commercial requirements: resources encrypted with a 32-byte
 * ResourceKey decrypt only with the same key (dev/no-handle path and authorized native op9 path),
 * a different key fails closed, and release builds without a ResourceKey fail at build time.</p>
 */
class ResourceKeySwitchTest {

    private static final byte[] RESOURCE_KEY = Crypto.sha256(
            "ki-28-resource-key".getBytes(StandardCharsets.UTF_8));
    private static final byte[] OTHER_RESOURCE_KEY = Crypto.sha256(
            "ki-28-other-resource-key".getBytes(StandardCharsets.UTF_8));
    private static final byte[] LEGACY_CONTENT_KEY = Crypto.sha256(
            "ki-28-legacy-content-key".getBytes(StandardCharsets.UTF_8));

    @AfterEach
    void clearProperties() {
        System.clearProperty("chimera.resourceKey");
        System.clearProperty("chimera.contentKey");
        System.clearProperty("chimera.auth.server");
        System.clearProperty("chimera.auth.pubkey");
        System.clearProperty("chimera.auth.autoHeartbeat");
    }

    // ---------------------------------------------------------------- dev/no-handle path

    @Test
    void resourceKeyEncryptedJarDecryptsOnlyWithSameKey(@TempDir Path work) throws Exception {
        Path jar = buildProtectedJar(work, RESOURCE_KEY, true);

        System.setProperty("chimera.resourceKey", Crypto.hex(RESOURCE_KEY));
        try (URLClassLoader loader = open(jar)) {
            Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true, loader);
            Class<?> lic = Class.forName("fixtures.Lic", true, loader);
            Class<?> bonus = Class.forName("fixtures.Bonus", true, loader);
            assertEquals("fixture-secret", lic.getMethod("label").invoke(null),
                    "string table must decrypt with the build ResourceKey");
            assertEquals(Boolean.TRUE, lic.getMethod("check", String.class).invoke(null, "OK-12"),
                    "hidden-class chunk + sealed chunk hash must verify with the same ResourceKey");
            assertEquals(81, ((Integer) lic.getMethod("score", int.class, int.class)
                    .invoke(null, 2, 3)).intValue());
            Object instance = bonus.getDeclaredConstructor().newInstance();
            assertEquals(52, ((Integer) bonus.getMethod("calc", int.class).invoke(instance, 7)).intValue());
            assertEquals(Boolean.TRUE, runtime.getMethod("isKeyHealthy").invoke(null));
        }

        // Same jar, wrong ResourceKey: must fail closed (poison, no catchable authorization error).
        System.setProperty("chimera.resourceKey", Crypto.hex(OTHER_RESOURCE_KEY));
        try (URLClassLoader loader = open(jar)) {
            Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true, loader);
            Class<?> lic = Class.forName("fixtures.Lic", true, loader);
            assertNotEquals("fixture-secret", lic.getMethod("label").invoke(null),
                    "a different ResourceKey must not decrypt the string table");
            assertEquals(Boolean.FALSE, lic.getMethod("check", String.class).invoke(null, "OK-12"),
                    "sealed chunk hash must fail with a different ResourceKey");
            assertEquals(Boolean.FALSE, runtime.getMethod("isKeyHealthy").invoke(null),
                    "wrong ResourceKey must poison the runtime");
        }
    }

    @Test
    void legacyContentKeyPropertyNoLongerUnlocksResourceKeyBuild(@TempDir Path work) throws Exception {
        Path jar = buildProtectedJar(work, RESOURCE_KEY, true);
        System.setProperty("chimera.contentKey", Crypto.hex(LEGACY_CONTENT_KEY));
        try (URLClassLoader loader = open(jar)) {
            Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true, loader);
            Class<?> lic = Class.forName("fixtures.Lic", true, loader);
            assertNotEquals("fixture-secret", lic.getMethod("label").invoke(null),
                    "the legacy content-key property must not decrypt ResourceKey-encrypted content");
            assertEquals(Boolean.FALSE, runtime.getMethod("isKeyHealthy").invoke(null));
        }
    }

    // ---------------------------------------------------------------- build-time gates

    @Test
    void releaseBuildWithoutResourceKeyFails(@TempDir Path work) throws Exception {
        Path input = buildFixtureJar(work);
        ChimeraConfig cfg = new ChimeraConfig();
        cfg.inputJar = input;
        cfg.outputJar = work.resolve("out.jar");
        cfg.release = true;
        cfg.keyMaterial = LEGACY_CONTENT_KEY;
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> new ChimeraEngine(cfg).run());
        assertTrue(error.getMessage().contains("ResourceKey"), error.getMessage());

        ChimeraConfig noKey = new ChimeraConfig();
        noKey.inputJar = input;
        noKey.outputJar = work.resolve("out2.jar");
        noKey.release = true;
        assertThrows(IllegalArgumentException.class, () -> new ChimeraEngine(noKey).run());
    }

    @Test
    void non32ByteResourceKeyIsRejected() {
        ChimeraConfig cfg = new ChimeraConfig();
        cfg.inputJar = Path.of("in.jar");
        cfg.outputJar = Path.of("out.jar");
        cfg.resourceKeyMaterial = new byte[16];
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class, cfg::validate);
        assertTrue(error.getMessage().contains("32 bytes"), error.getMessage());
    }

    @Test
    void devFallbackStillWorksWithoutResourceKeyWhenNotRelease(@TempDir Path work) throws Exception {
        Path input = buildFixtureJar(work);
        ChimeraConfig cfg = new ChimeraConfig();
        cfg.inputJar = input;
        cfg.outputJar = work.resolve("dev-fallback.jar");
        cfg.keyMaterial = LEGACY_CONTENT_KEY;
        cfg.nativeOutDir = work.resolve("native");
        new ChimeraEngine(cfg).run();

        System.setProperty("chimera.contentKey", Crypto.hex(LEGACY_CONTENT_KEY));
        try (URLClassLoader loader = open(cfg.outputJar)) {
            Class<?> lic = Class.forName("fixtures.Lic", true, loader);
            assertEquals("fixture-secret", lic.getMethod("label").invoke(null),
                    "dev fallback must keep working for non-release builds");
        }
    }

    // ---------------------------------------------------------------- authorized native op9 path

    @Test
    void authorizedPathUsesActivateResourceKeyAndFailsClosedOnMismatch(@TempDir Path work) throws Exception {
        NativeAuthLibrary.prepareIsolatedCopy();
        try (MockLicenseServer server = new MockLicenseServer()) {
            System.setProperty("chimera.auth.autoHeartbeat", "false");

            Path matching = buildAuthJar(work.resolve("matching"), server, server.resourceKey());
            try (URLClassLoader loader = open(matching)) {
                Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true, loader);
                assertTrue(authenticate(runtime), "activation must succeed");
                assertNull(privateField(runtime, "contentKeyMaterial"),
                        "authorized mode must not retain the user content key");
                assertNull(privateField(runtime, "kek"),
                        "authorized mode must not retain the derived KEK");
                assertNull(privateField(runtime, "resourceKeyMaterial"),
                        "authorized mode must not retain the ResourceKey");
                Class<?> lic = Class.forName("fixtures.Lic", true, loader);
                assertEquals("fixture-secret", lic.getMethod("label").invoke(null),
                        "resource_ck ResourceKey must decrypt the string table through op9");
                assertEquals(Boolean.TRUE, lic.getMethod("check", String.class).invoke(null, "OK-12"),
                        "sealed manifest/chunk-hash must verify through op9");
                assertEquals(Boolean.TRUE, runtime.getMethod("isKeyHealthy").invoke(null));
            }

            // Build with a different ResourceKey than activate delivers: authentication still
            // succeeds, but every resource decrypt/verification must fail closed.
            Path mismatched = buildAuthJar(work.resolve("mismatch"), server, OTHER_RESOURCE_KEY);
            try (URLClassLoader loader = open(mismatched)) {
                Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true, loader);
                assertTrue(authenticate(runtime), "activation itself must still succeed");
                Class<?> lic = Class.forName("fixtures.Lic", true, loader);
                assertNotEquals("fixture-secret", lic.getMethod("label").invoke(null),
                        "activate ResourceKey mismatch must not decrypt content");
                assertEquals(Boolean.FALSE, lic.getMethod("check", String.class).invoke(null, "OK-12"));
                assertEquals(Boolean.FALSE, runtime.getMethod("isKeyHealthy").invoke(null),
                        "mismatched ResourceKey must poison the runtime");
            }
        }
    }

    // ---------------------------------------------------------------- helpers

    private static Path buildProtectedJar(Path work, byte[] resourceKey, boolean release) throws Exception {
        Path input = buildFixtureJar(work);
        Path output = work.resolve("protected.jar");
        ChimeraConfig cfg = new ChimeraConfig();
        cfg.inputJar = input;
        cfg.outputJar = output;
        cfg.resourceKeyMaterial = resourceKey.clone();
        cfg.release = release;
        cfg.nativeOutDir = work.resolve("native");
        cfg.integrityManifest = true;
        new ChimeraEngine(cfg).run();
        return output;
    }

    private static Path buildAuthJar(Path work, MockLicenseServer server, byte[] resourceKey)
            throws Exception {
        Files.createDirectories(work);
        Path input = buildFixtureJar(work);
        Path output = work.resolve("protected-auth.jar");
        ChimeraConfig cfg = new ChimeraConfig();
        cfg.inputJar = input;
        cfg.outputJar = output;
        cfg.resourceKeyMaterial = resourceKey.clone();
        cfg.release = true;
        cfg.nativeOutDir = work.resolve("native");
        cfg.integrityManifest = true;
        cfg.authServer = server.baseUrl();
        cfg.authPubkey = server.publicKeyBase64();
        cfg.authHeartbeatMs = 1000L;
        new ChimeraEngine(cfg).run();
        return output;
    }

    private static Path buildFixtureJar(Path work) throws Exception {
        Files.createDirectories(work);
        Path input = work.resolve("fixtures.jar");
        try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(input))) {
            for (String name : new String[]{"fixtures/Lic.class", "fixtures/Bonus.class"}) {
                try (InputStream in = ResourceKeySwitchTest.class.getClassLoader()
                        .getResourceAsStream(name)) {
                    assertNotNull(in, "missing fixture " + name);
                    out.putNextEntry(new ZipEntry(name));
                    out.write(in.readAllBytes());
                    out.closeEntry();
                }
            }
        }
        return input;
    }

    private static URLClassLoader open(Path jar) throws Exception {
        NativeAuthLibrary.prepareIsolatedCopy();
        return new URLClassLoader(new URL[]{jar.toUri().toURL()},
                ClassLoader.getPlatformClassLoader());
    }

    private static boolean authenticate(Class<?> runtime) throws Exception {
        return Boolean.TRUE.equals(runtime.getMethod("authenticate",
                String.class, String.class, String.class).invoke(null,
                MockLicenseServer.ACCOUNT, MockLicenseServer.PASSWORD, MockLicenseServer.HWID));
    }

    private static Object privateField(Class<?> runtime, String name) throws Exception {
        Field field = runtime.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(null);
    }
}
