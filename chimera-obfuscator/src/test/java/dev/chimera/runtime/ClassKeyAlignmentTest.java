package dev.chimera.runtime;

import dev.chimera.auth.MockLicenseServer;
import dev.chimera.auth.NativeAuthLibrary;
import dev.chimera.core.ChimeraConfig;
import dev.chimera.core.ChimeraEngine;
import dev.chimera.core.ClassKeyDerivation;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * P1-1: the CHENC1 class-body key must not exist anywhere in the shipped jar; native derives it
 * from the ResourceKey held by the authorized SessionHandle.
 *
 * <p>Two contracts are asserted here. (1) Alignment: the build-side replica
 * ({@link ClassKeyDerivation}) and {@code nativeDeriveClassKey} produce the same 32 bytes for the
 * same ResourceKey, so build-time encryption and runtime decryption cannot drift apart. (2) Absence:
 * the embedded agent jar carries no key material, and no key can be derived without a live handle
 * (fail-closed).</p>
 */
class ClassKeyAlignmentTest {

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
        System.clearProperty("chimera.resourceKey");
        if (server != null) {
            server.close();
        }
    }

    @Test
    void nativeDerivationMatchesBuildDerivationByteForByte(@TempDir Path work) throws Exception {
        byte[] resourceKey = server.resourceKey();
        Path jar = buildProtectedJar(work, resourceKey, false);
        byte[] expected = ClassKeyDerivation.derive(resourceKey);
        assertEquals(32, expected.length);

        try (URLClassLoader loader = open(jar)) {
            Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true, loader);
            Assumptions.assumeTrue(Boolean.TRUE.equals(
                            runtime.getMethod("nativeAuthAvailable").invoke(null)),
                    "native auth library must be loadable for this check");

            assertNull(runtime.getMethod("deriveClassKey").invoke(null),
                    "no authorized handle yet: the class key must not exist");

            assertTrue(authenticate(runtime), "native activation must succeed for real");
            Object derived = runtime.getMethod("deriveClassKey").invoke(null);
            assertNotNull(derived, "an authorized handle must yield the class key");
            assertArrayEquals(expected, (byte[]) derived,
                    "build-time derivation and nativeDeriveClassKey must agree byte for byte");

            // Fail-closed: revoking the handle removes the key instead of falling back to anything.
            runtime.getMethod("nativeRevokeAllHandles").invoke(null);
            assertNull(runtime.getMethod("deriveClassKey").invoke(null),
                    "a revoked handle must not yield the class key");
        }
    }

    @Test
    void agentJarCarriesNoKeyMaterialAndClassesStayCiphertext(@TempDir Path work) throws Exception {
        Path jar = buildProtectedJar(work, server.resourceKey(), true);
        int encrypted = 0;
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            var entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (!entry.getName().endsWith(".class")) {
                    continue;
                }
                byte[] bytes;
                try (InputStream in = zip.getInputStream(entry)) {
                    bytes = in.readAllBytes();
                }
                if (isChEnc(bytes)) {
                    encrypted++;
                }
            }
            assertTrue(encrypted > 0, "the fixture classes must be CHENC1 ciphertext");

            ZipEntry agent = zip.getEntry("chimera/attach/agent.jar");
            assertNotNull(agent, "the agent jar must still be embedded");
            byte[] agentJar;
            try (InputStream in = zip.getInputStream(agent)) {
                agentJar = in.readAllBytes();
            }
            try (ZipFile agentZip = new ZipFile(writeTemp(work.resolve("agent-extracted.jar"), agentJar).toFile())) {
                var agentEntries = agentZip.entries();
                while (agentEntries.hasMoreElements()) {
                    String name = agentEntries.nextElement().getName();
                    assertFalse(name.equals("chimera/attach/key.bin"),
                            "P1-1: the agent jar must not carry the class-body key");
                }
                assertNotNull(agentZip.getEntry("dev/chimera/attach/AttachAgent.class"));
            }
        }
    }

    // ------------------------------------------------------------------ helpers

    private static boolean isChEnc(byte[] bytes) {
        byte[] magic = {'C', 'H', 'E', 'N', 'C', '1', 0};
        if (bytes.length < magic.length) {
            return false;
        }
        for (int i = 0; i < magic.length; i++) {
            if (bytes[i] != magic[i]) {
                return false;
            }
        }
        return true;
    }

    private static Path writeTemp(Path target, byte[] data) throws Exception {
        Files.write(target, data);
        return target;
    }

    private static boolean authenticate(Class<?> runtime) throws Exception {
        Object result = runtime.getMethod("authenticate", String.class, String.class, String.class)
                .invoke(null, MockLicenseServer.ACCOUNT, MockLicenseServer.PASSWORD,
                        MockLicenseServer.HWID);
        return Boolean.TRUE.equals(result);
    }

    private static URLClassLoader open(Path jar) throws Exception {
        // Each embedded runtime loads its own native DLL copy; the dev DLL is reused (no rebuild).
        NativeAuthLibrary.prepareIsolatedCopy();
        return new URLClassLoader(new URL[]{jar.toUri().toURL()}, ClassLoader.getPlatformClassLoader());
    }

    private Path buildProtectedJar(Path work, byte[] resourceKey, boolean classEncrypt)
            throws Exception {
        Path input = work.resolve("fixtures.jar");
        try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(input))) {
            for (String name : new String[]{"fixtures/Lic.class", "fixtures/Bonus.class"}) {
                try (InputStream in = ClassKeyAlignmentTest.class.getClassLoader()
                        .getResourceAsStream(name)) {
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
        config.authServer = server.baseUrl();
        config.authPubkey = server.publicKeyBase64();
        config.authHeartbeatMs = 1000L;
        config.classEncrypt = classEncrypt;
        new ChimeraEngine(config).run();
        return output;
    }
}
