package dev.chimera;

import dev.chimera.auth.MockLicenseServer;
import dev.chimera.auth.NativeAuthLibrary;
import dev.chimera.core.ChimeraConfig;
import dev.chimera.core.ChimeraEngine;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end module 3/4 + M3: the license server hands out the product content key, the client
 * handshake installs it, and the encrypted string/fragment content of an obfuscated jar decrypts.
 *
 * <p>This is the test that proves the handshake is not a mock-only exercise: the build-time key
 * is the server's content key, the baked {@code /chimera/auth.dat} is used (no server property
 * override), and the loaded protected class only produces the real string when the handshake
 * succeeded.</p>
 */
public class AuthEndToEndTest {

    private static byte[] fixtureClass(String name) throws Exception {
        try (InputStream in = AuthEndToEndTest.class.getClassLoader().getResourceAsStream(name)) {
            assertNotNull(in, "missing fixture " + name);
            return in.readAllBytes();
        }
    }

    private static Path buildFixtureJar(Path jar) throws Exception {
        Files.createDirectories(jar.getParent());
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(jar))) {
            for (String name : new String[]{"fixtures/Lic.class", "fixtures/Bonus.class"}) {
                zos.putNextEntry(new ZipEntry(name));
                zos.write(fixtureClass(name));
                zos.closeEntry();
            }
        }
        return jar;
    }

    @Test
    public void serverIssuedContentKeyUnlocksObfuscatedJar() throws Exception {
        // The output jar's ChimeraRuntime has its own classloader: give it an isolated native copy.
        NativeAuthLibrary.prepareIsolatedCopy();
        System.clearProperty("chimera.runtime.hash.skip");
        try (MockLicenseServer server = new MockLicenseServer()) {
            Path work = Files.createTempDirectory("chimera-auth-e2e");
            Path in = buildFixtureJar(work.resolve("fixtures.jar"));
            Path out = work.resolve("fixtures-auth-obf.jar");

            ChimeraConfig cfg = new ChimeraConfig();
            cfg.inputJar = in;
            cfg.outputJar = out;
            cfg.nativeOutDir = work.resolve("native");
            cfg.resourceKeyMaterial = server.resourceKey();
            cfg.integrityManifest = true;
            cfg.authServer = server.baseUrl();
            cfg.authPubkey = server.publicKeyBase64();
            cfg.authHeartbeatMs = 1000L;
            new ChimeraEngine(cfg).run();

            String previousServer = System.getProperty("chimera.auth.server");
            String previousPubkey = System.getProperty("chimera.auth.pubkey");
            String previousHeartbeat = System.getProperty("chimera.auth.autoHeartbeat");
            String previousKey = System.getProperty("chimera.contentKey");
            String previousResourceKey = System.getProperty("chimera.resourceKey");
            System.clearProperty("chimera.auth.server");
            System.clearProperty("chimera.auth.pubkey");
            System.clearProperty("chimera.contentKey");
            System.clearProperty("chimera.resourceKey");
            System.setProperty("chimera.auth.autoHeartbeat", "false");
            try (URLClassLoader cl = new URLClassLoader(new URL[]{out.toUri().toURL()},
                    ClassLoader.getPlatformClassLoader())) {
                Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true, cl);
                Method authenticate = runtime.getMethod("authenticate",
                        String.class, String.class, String.class);
                assertTrue((Boolean) authenticate.invoke(null, MockLicenseServer.ACCOUNT,
                        MockLicenseServer.PASSWORD, MockLicenseServer.HWID),
                        "activation against the mock server must succeed");
                assertTrue((Boolean) runtime.getMethod("isKeyHealthy").invoke(null));

                Class<?> lic = Class.forName("fixtures.Lic", true, cl);
                assertEquals("fixture-secret", lic.getMethod("label").invoke(null),
                        "the ResourceKey delivered in resource_ck must decrypt the string table via op9");
                assertEquals(81, ((Integer) lic.getMethod("score", int.class, int.class)
                        .invoke(null, 2, 3)).intValue());

                long firstEpoch = (Long) runtime.getMethod("sessionEpoch").invoke(null);
                assertTrue((Boolean) runtime.getMethod("heartbeatNow").invoke(null));
                long secondEpoch = (Long) runtime.getMethod("sessionEpoch").invoke(null);
                assertNotEquals(firstEpoch, secondEpoch, "heartbeat must rotate the server nonce");
                assertTrue((Boolean) runtime.getMethod("isKeyHealthy").invoke(null));
            } finally {
                restore("chimera.auth.server", previousServer);
                restore("chimera.auth.pubkey", previousPubkey);
                restore("chimera.auth.autoHeartbeat", previousHeartbeat);
                restore("chimera.contentKey", previousKey);
                restore("chimera.resourceKey", previousResourceKey);
            }
        }
    }

    private static void restore(String name, String value) {
        if (value == null) {
            System.clearProperty(name);
        } else {
            System.setProperty(name, value);
        }
    }
}
