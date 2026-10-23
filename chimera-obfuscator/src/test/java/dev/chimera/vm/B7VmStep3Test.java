package dev.chimera.vm;

import dev.chimera.auth.MockLicenseServer;
import dev.chimera.auth.NativeAuthLibrary;
import dev.chimera.core.ChimeraConfig;
import dev.chimera.core.ChimeraEngine;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.lang.reflect.Method;
import java.net.URI;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * B7 step 2 (op10) end-to-end Java-side test, using the <b>release</b> DLL so the handle starts in
 * the real release PENDING state:
 *
 * <ol>
 *   <li>manual activation (nativeSetAuthContext -> nativeCreateClientKey -> HTTP activate ->
 *       nativeVerifyAuth) returns a PENDING handle; canary (op5) must be 0;</li>
 *   <li>ChimeraVmRuntime.runDecisionProgram(handle) sends nativeCompute op10; transcript/sig stay
 *       in native memory; canary becomes 1;</li>
 *   <li>repeating op10 is idempotent; a tampered-signature (poison) handle never promotes;</li>
 *   <li>handle==0 fails closed (false, no exception).</li>
 * </ol>
 *
 * <p>The release DLL has no dev QA hooks: this test proves the production op10 path without
 * nativeForcePendingForTest. If the release DLL is not present the test is skipped explicitly.</p>
 */
public class B7VmStep3Test {

    private static final int OP_CANARY = 5;
    private static final int OP_RUN_DECISION = 10;

    @Test
    void releasePendingHandleIsPromotedByOp10AndCanary() throws Exception {
        Path releaseDir = releaseNativeDir();
        Assumptions.assumeTrue(Files.isRegularFile(releaseDir.resolve("chimera_auth.dll")),
                "release DLL missing; op10 release-PENDING test NOT executed: " + releaseDir);

        String previousDevDir = System.getProperty("chimera.native.dev.dir");
        String previousAuthPath = System.getProperty("chimera.native.auth.path");
        String previousAuto = System.getProperty("chimera.auth.autoHeartbeat");
        String previousServer = System.getProperty("chimera.auth.server");
        String previousPubkey = System.getProperty("chimera.auth.pubkey");
        String previousKey = System.getProperty("chimera.contentKey");
        System.setProperty("chimera.native.dev.dir", releaseDir.toString());
        System.setProperty("chimera.auth.autoHeartbeat", "false");
        System.clearProperty("chimera.auth.server");
        System.clearProperty("chimera.auth.pubkey");
        System.clearProperty("chimera.contentKey");
        NativeAuthLibrary.prepareIsolatedCopy();
        try (MockLicenseServer server = new MockLicenseServer()) {
            Path work = Files.createTempDirectory("chimera-b7-step3");
            Path jar = buildAuthJar(work, server);
            try (URLClassLoader loader = new URLClassLoader(new URL[]{jar.toUri().toURL()},
                    ClassLoader.getPlatformClassLoader())) {
                Class<?> chimeraRuntime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true, loader);
                Assumptions.assumeTrue((Boolean) chimeraRuntime.getMethod("nativeAuthAvailable").invoke(null),
                        "release native auth DLL unavailable in the isolated loader");
                assertEquals(Boolean.FALSE, chimeraRuntime.getMethod("isDevNativeBuild").invoke(null),
                        "this test must run against the release DLL (no dev hooks)");
                // A release DLL built for delivery pins the licence-server key at compile time, so
                // nativeSetAuthContext ignores the synthetic key this test supplies and no handle
                // can ever reach VALID. Skip rather than assert a weaker behaviour.
                Assumptions.assumeFalse(
                        (Boolean) chimeraRuntime.getMethod("nativeAuthPubkeyPinned").invoke(null),
                        "release DLL carries a build-pinned auth key; the synthetic test server "
                                + "cannot sign for it (see PocAuthDatTamper / gate-diag SECURITY line)");

                Method nativeSetContext = chimeraRuntime.getMethod("nativeSetAuthContext",
                        byte[].class, byte[].class);
                Method nativeCreateClient = chimeraRuntime.getMethod("nativeCreateClientKey");
                Method nativeVerifyAuth = chimeraRuntime.getMethod("nativeVerifyAuth",
                        byte[].class, byte[].class);
                Method nativeCompute = chimeraRuntime.getMethod("nativeCompute", long.class, byte[].class);
                Class<?> vmRuntime = Class.forName("dev.chimera.runtime.ChimeraVmRuntime", true, loader);
                Method runDecision = vmRuntime.getMethod("runDecisionProgram", long.class);
                Method runDecisionCurrent = vmRuntime.getMethod("runDecisionProgramForCurrentSession");

                // --- handle 1: wrapper with explicit handle -------------------------------
                long pending = activate(chimeraRuntime, server, nativeSetContext, nativeCreateClient,
                        nativeVerifyAuth);
                assertNotEquals(0L, pending);
                assertEquals(0L, canary(nativeCompute, pending),
                        "release nativeVerifyAuth must return a PENDING handle (canary=0)");
                assertEquals(Boolean.TRUE, runDecision.invoke(null, pending),
                        "op10 native call must complete");
                assertEquals(1L, canary(nativeCompute, pending),
                        "op10 must promote the release PENDING handle to VALID (canary=1)");
                assertEquals(Boolean.TRUE, runDecision.invoke(null, pending));
                assertEquals(1L, canary(nativeCompute, pending), "op10 must be idempotent");

                // --- handle 2: convenience path reads the installed handle -----------------
                long pending2 = activate(chimeraRuntime, server, nativeSetContext, nativeCreateClient,
                        nativeVerifyAuth);
                java.lang.reflect.Field field = chimeraRuntime.getDeclaredField("nativeSessionHandle");
                field.setAccessible(true);
                field.setLong(null, pending2);
                assertEquals(0L, canary(nativeCompute, pending2), "second handle also starts PENDING");
                assertEquals(Boolean.TRUE, runDecisionCurrent.invoke(null));
                assertEquals(1L, canary(nativeCompute, pending2));

                // --- tampered signature: poison handle and op10 must not promote ------------
                server.setTamperSignature(true);
                long poisoned = activate(chimeraRuntime, server, nativeSetContext, nativeCreateClient,
                        nativeVerifyAuth);
                assertNotEquals(0L, poisoned, "poison path still returns a long-shaped handle");
                assertEquals(0L, canary(nativeCompute, poisoned), "tampered activation must be poisoned");
                runDecision.invoke(null, poisoned); // shape-only call, no decision oracle
                assertEquals(0L, canary(nativeCompute, poisoned),
                        "op10 must never promote a poisoned handle");
                server.setTamperSignature(false);

                // --- zero handle fails closed ----------------------------------------------
                assertEquals(Boolean.FALSE, runDecision.invoke(null, 0L));
            }
        } finally {
            restore("chimera.native.dev.dir", previousDevDir);
            restore("chimera.native.auth.path", previousAuthPath);
            restore("chimera.auth.autoHeartbeat", previousAuto);
            restore("chimera.auth.server", previousServer);
            restore("chimera.auth.pubkey", previousPubkey);
            restore("chimera.contentKey", previousKey);
        }
    }

    // ------------------------------------------------------------------ harness

    private static long activate(Class<?> chimeraRuntime, MockLicenseServer server,
                                 Method setContext, Method createClient, Method verifyAuth) throws Exception {
        byte[] clientPublic = (byte[]) createClient.invoke(null);
        assertNotNull(clientPublic);
        byte[] pubkeyRaw = Base64.getDecoder().decode(server.publicKeyBase64());
        setContext.invoke(null, pubkeyRaw, MockLicenseServer.ACCOUNT.getBytes(StandardCharsets.UTF_8));

        String request = "{\"account\":\"" + MockLicenseServer.ACCOUNT
                + "\",\"password\":\"" + MockLicenseServer.PASSWORD
                + "\",\"hwid\":\"" + MockLicenseServer.HWID
                + "\",\"client_ephemeral_pub\":\""
                + Base64.getEncoder().encodeToString(clientPublic) + "\"}";
        HttpClient http = HttpClient.newHttpClient();
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(server.baseUrl() + "/api/v1/license/activate"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(request))
                .build();
        HttpResponse<String> response = http.send(httpRequest, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), "mock activation must succeed");
        return ((Number) verifyAuth.invoke(null,
                response.body().getBytes(StandardCharsets.UTF_8),
                MockLicenseServer.HWID.getBytes(StandardCharsets.UTF_8))).longValue();
    }

    private static long canary(Method nativeCompute, long handle) throws Exception {
        byte[] value = (byte[]) nativeCompute.invoke(null, handle, new byte[]{(byte) OP_CANARY});
        assertNotNull(value);
        assertEquals(8, value.length, "canary must keep the 8-byte shape");
        long result = 0L;
        for (byte b : value) {
            result = (result << 8) | (b & 0xffL);
        }
        return result;
    }

    private static Path releaseNativeDir() {
        Path fromWorkingDir = Path.of(System.getProperty("user.dir"), "native", "windows-x64")
                .toAbsolutePath().normalize();
        if (Files.isRegularFile(fromWorkingDir.resolve("chimera_auth.dll"))) {
            return fromWorkingDir;
        }
        return Path.of("native", "windows-x64").toAbsolutePath().normalize();
    }

    private static Path buildAuthJar(Path work, MockLicenseServer server) throws Exception {
        Path input = work.resolve("fixtures.jar");
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(input))) {
            zos.putNextEntry(new ZipEntry("fixtures/Lic.class"));
            zos.write(fixtureClass("fixtures/Lic.class"));
            zos.closeEntry();
        }
        Path output = work.resolve("obfuscated.jar");
        ChimeraConfig cfg = new ChimeraConfig();
        cfg.inputJar = input;
        cfg.outputJar = output;
        cfg.nativeOutDir = work.resolve("native");
        cfg.keyMaterial = server.contentKey();
        cfg.integrityManifest = true;
        cfg.authServer = server.baseUrl();
        cfg.authPubkey = server.publicKeyBase64();
        cfg.authHeartbeatMs = 60_000L;
        new ChimeraEngine(cfg).run();
        return output;
    }

    private static byte[] fixtureClass(String name) throws Exception {
        try (InputStream in = B7VmStep3Test.class.getClassLoader().getResourceAsStream(name)) {
            assertNotNull(in, "missing fixture " + name);
            return in.readAllBytes();
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
