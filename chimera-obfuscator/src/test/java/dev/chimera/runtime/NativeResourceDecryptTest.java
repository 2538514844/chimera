package dev.chimera.runtime;

import dev.chimera.auth.MockLicenseServer;
import dev.chimera.auth.NativeAuthLibrary;
import dev.chimera.core.ChimeraConfig;
import dev.chimera.core.ChimeraEngine;
import dev.chimera.crypto.Crypto;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Night task: authorized resource decryption must go through nativeCompute DECRYPT_DATA (op 9).
 * Java never receives the UserContentKey/ResourceKey in authorized mode and there is no fake
 * Java wiring: authenticate must call nativeVerifyAuth for real and a release PENDING handle is
 * a real failure, not a retry/fake-valid path.
 *
 * <p>The legacy Java HKDF+AES-GCM path is only for jars without a native SessionHandle
 * (demo/no-handle builds) and is never used as a fallback in authorized mode.</p>
 */
class NativeResourceDecryptTest {

    private static final String FIXTURE_SECRET = "fixture-secret";
    private MockLicenseServer server;

    @BeforeEach
    void startServer() throws Exception {
        server = new MockLicenseServer();
        System.setProperty("chimera.auth.server", server.baseUrl());
        System.setProperty("chimera.auth.pubkey", server.publicKeyBase64());
        System.setProperty("chimera.auth.autoHeartbeat", "false");
    }

    @AfterEach
    void stopServer() {
        System.clearProperty("chimera.auth.server");
        System.clearProperty("chimera.auth.pubkey");
        System.clearProperty("chimera.auth.autoHeartbeat");
        System.clearProperty("chimera.contentKey");
        System.clearProperty("chimera.resourceKey");
        if (server != null) server.close();
    }

    @Test
    void legacyPathWithoutHandleDecryptsAndFailsClosedOnTamper(@TempDir Path work) throws Exception {
        // KI-28: the legacy dev path now consumes the same product ResourceKey the server delivers
        // inside resource_ck; the global content key is no longer the build-time encryption key.
        byte[] resourceKey = server.resourceKey();
        Path jar = buildProtectedJar(work, resourceKey);

        System.setProperty("chimera.resourceKey", Crypto.hex(resourceKey));
        try (URLClassLoader loader = open(jar)) {
            Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true, loader);
            Class<?> lic = Class.forName("fixtures.Lic", true, loader);
            assertEquals(FIXTURE_SECRET, lic.getMethod("label").invoke(null),
                    "legacy no-handle path must decrypt the string table with the resource key property");
            assertEquals(Boolean.TRUE, lic.getMethod("check", String.class).invoke(null, "OK-12"));
            assertEquals(81, ((Integer) lic.getMethod("score", int.class, int.class).invoke(null, 2, 3)).intValue());
            assertEquals(Boolean.TRUE, runtime.getMethod("isKeyHealthy").invoke(null));
        }

        Path tamperedStrings = rewriteSingleEntry(jar, work.resolve("strings-tampered.jar"),
                "chimera/strings.dat", false, true);
        try (URLClassLoader loader = open(tamperedStrings)) {
            Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true, loader);
            Class<?> lic = Class.forName("fixtures.Lic", true, loader);
            assertNotEquals(FIXTURE_SECRET, lic.getMethod("label").invoke(null),
                    "tampered string ciphertext must not produce the healthy value");
            assertEquals(Boolean.FALSE, runtime.getMethod("isKeyHealthy").invoke(null));
        }

        String chunkName = firstChunkName(jar);
        assertNotNull(chunkName);
        Path tamperedChunk = rewriteSingleEntry(jar, work.resolve("chunk-tampered.jar"),
                chunkName, false, true);
        try (URLClassLoader loader = open(tamperedChunk)) {
            Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true, loader);
            Class<?> lic = Class.forName("fixtures.Lic", true, loader);
            assertEquals(FIXTURE_SECRET, lic.getMethod("label").invoke(null));
            assertEquals(Boolean.FALSE, lic.getMethod("check", String.class).invoke(null, "OK-12"),
                    "tampered chunk ciphertext must degrade to a poison value, not throw");
            assertEquals(Boolean.FALSE, runtime.getMethod("isKeyHealthy").invoke(null));
        }
    }

    @Test
    void authorizedPathDecryptsNativelyAndNeverHoldsContentKey(@TempDir Path work) throws Exception {
        Path jar = buildProtectedJar(work, server.resourceKey());
        try (URLClassLoader loader = open(jar)) {
            Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true, loader);
            assertTrue(authenticate(runtime),
                    "native activation must succeed for real; release PENDING is a real failure "
                            + "(no Java fake-valid wiring)");
            assertTrue((Boolean) runtime.getMethod("isKeyHealthy").invoke(null));

            // Architecture red line: authorized mode must not retain UserContentKey in Java.
            assertNull(privateField(runtime, "contentKeyMaterial"),
                    "authorized mode must not retain the raw content key in Java");
            assertNull(privateField(runtime, "kek"),
                    "authorized mode must not retain the derived KEK in Java");
            assertNull(privateField(runtime, "resourceKeyMaterial"),
                    "authorized mode must not retain the ResourceKey in Java");

            Class<?> lic = Class.forName("fixtures.Lic", true, loader);
            assertEquals(FIXTURE_SECRET, lic.getMethod("label").invoke(null),
                    "authorized string decryption must go through native DECRYPT_DATA (op 9)");
            assertEquals(Boolean.TRUE, lic.getMethod("check", String.class).invoke(null, "OK-12"),
                    "authorized chunk decryption must go through native DECRYPT_DATA (op 9)");
            assertEquals(81, ((Integer) lic.getMethod("score", int.class, int.class).invoke(null, 2, 3)).intValue());
            assertEquals(Boolean.TRUE, runtime.getMethod("isKeyHealthy").invoke(null));
        }
    }

    @Test
    void authorizedTamperedCiphertextFailsClosed(@TempDir Path work) throws Exception {
        Path jar = buildProtectedJar(work, server.resourceKey());

        Path tamperedStrings = rewriteSingleEntry(jar, work.resolve("auth-strings-tampered.jar"),
                "chimera/strings.dat", false, true);
        try (URLClassLoader loader = open(tamperedStrings)) {
            Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true, loader);
            assertTrue(authenticate(runtime), "native activation must succeed for real");
            Class<?> lic = Class.forName("fixtures.Lic", true, loader);
            assertNotEquals(FIXTURE_SECRET, lic.getMethod("label").invoke(null),
                    "tampered authorized string ciphertext must not decrypt");
            assertEquals(Boolean.FALSE, runtime.getMethod("isKeyHealthy").invoke(null));
        }

        String chunkName = firstChunkName(jar);
        assertNotNull(chunkName);
        Path tamperedChunk = rewriteSingleEntry(jar, work.resolve("auth-chunk-tampered.jar"),
                chunkName, false, true);
        try (URLClassLoader loader = open(tamperedChunk)) {
            Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true, loader);
            assertTrue(authenticate(runtime), "native activation must succeed for real");
            Class<?> lic = Class.forName("fixtures.Lic", true, loader);
            assertEquals(Boolean.FALSE, lic.getMethod("check", String.class).invoke(null, "OK-12"),
                    "tampered authorized chunk must return a poison value, not throw");
            assertEquals(Boolean.FALSE, runtime.getMethod("isKeyHealthy").invoke(null));
        }
    }

    // ------------------------------------------------------------------ runtime helpers

    private static boolean authenticate(Class<?> runtime) throws Exception {
        Method method = runtime.getMethod("authenticate", String.class, String.class, String.class);
        Object result = method.invoke(null, MockLicenseServer.ACCOUNT,
                MockLicenseServer.PASSWORD, MockLicenseServer.HWID);
        return Boolean.TRUE.equals(result);
    }

    private static Object privateField(Class<?> runtime, String name) throws Exception {
        Field field = runtime.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(null);
    }

    private static URLClassLoader open(Path jar) throws Exception {
        // Each embedded runtime loads its own native DLL copy; the dev DLL is reused (no rebuild).
        NativeAuthLibrary.prepareIsolatedCopy();
        return new URLClassLoader(new URL[]{jar.toUri().toURL()}, ClassLoader.getPlatformClassLoader());
    }

    // ------------------------------------------------------------------ jar/build helpers

    private Path buildProtectedJar(Path work, byte[] resourceKey) throws Exception {
        Path input = work.resolve("fixtures.jar");
        try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(input))) {
            for (String name : new String[]{"fixtures/Lic.class", "fixtures/Bonus.class"}) {
                try (InputStream in = NativeResourceDecryptTest.class.getClassLoader().getResourceAsStream(name)) {
                    assertNotNull(in, "missing fixture " + name);
                    out.putNextEntry(new ZipEntry(name));
                    out.write(in.readAllBytes());
                    out.closeEntry();
                }
            }
        }
        Path output = work.resolve("fixtures-obf.jar");
        ChimeraConfig config = new ChimeraConfig();
        config.inputJar = input;
        config.outputJar = output;
        config.resourceKeyMaterial = resourceKey.clone();
        config.nativeOutDir = work.resolve("native");
        config.integrityManifest = true;
        config.authServer = server.baseUrl();
        config.authPubkey = server.publicKeyBase64();
        config.authHeartbeatMs = 1000L;
        new ChimeraEngine(config).run();
        return output;
    }

    private static Path rewriteSingleEntry(Path source, Path target, String entryName,
                                           boolean remove, boolean flipLastByte) throws Exception {
        boolean touched = false;
        try (ZipFile in = new ZipFile(source.toFile());
             ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(target))) {
            var entries = in.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.getName().equals(entryName)) {
                    touched = true;
                    if (remove) continue;
                }
                byte[] data;
                try (InputStream stream = in.getInputStream(entry)) { data = stream.readAllBytes(); }
                if (entry.getName().equals(entryName) && flipLastByte && data.length > 0) {
                    data = data.clone();
                    data[data.length - 1] ^= 0x01;
                }
                out.putNextEntry(new ZipEntry(entry.getName()));
                out.write(data);
                out.closeEntry();
            }
        }
        assertTrue(touched, "test setup must find " + entryName);
        return target;
    }

    private static String firstChunkName(Path jar) throws Exception {
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            var entries = zip.entries();
            while (entries.hasMoreElements()) {
                String name = entries.nextElement().getName();
                if (name.startsWith("chimera/chunks/chunk_") && name.endsWith(".bin")) return name;
            }
        }
        return null;
    }
}
