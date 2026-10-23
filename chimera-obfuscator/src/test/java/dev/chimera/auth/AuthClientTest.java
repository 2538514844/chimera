package dev.chimera.auth;

import dev.chimera.runtime.ChimeraRuntime;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Module 4 tests: the client must verify the Ed25519 response signature before unwrapping the
 * content key, install both key and nonce, rotate the session on heartbeat, and degrade via poison
 * (never throw) on a fake/tampered/unreachable server.
 */
class AuthClientTest {

    private MockLicenseServer server;

    @BeforeAll
    static void loadNativeAuth() {
        NativeAuthLibrary.prepareIsolatedCopy();
    }

    @BeforeEach
    void setUp() throws Exception {
        server = new MockLicenseServer();
        System.setProperty("chimera.auth.server", server.baseUrl());
        System.setProperty("chimera.auth.pubkey", server.publicKeyBase64());
        System.setProperty("chimera.auth.autoHeartbeat", "false");
        // Unit tests do not have a protected jar's /chimera/runtime.hash resource.
        System.setProperty("chimera.runtime.hash.skip", "true");
        resetRuntime();
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.close();
        }
        System.clearProperty("chimera.auth.server");
        System.clearProperty("chimera.auth.pubkey");
        System.clearProperty("chimera.auth.autoHeartbeat");
        System.clearProperty("chimera.runtime.hash.skip");
        resetRuntime();
    }

    private static void resetRuntime() {
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 0x5a);
        ChimeraRuntime.setContentKey(key);
    }

    @Test
    void activateInstallsContentKeyAndSession() {
        assertTrue(ChimeraRuntime.authenticate(MockLicenseServer.ACCOUNT,
                MockLicenseServer.PASSWORD, MockLicenseServer.HWID));
        assertTrue(ChimeraRuntime.isKeyHealthy());
        assertEquals(1, server.activations());
        assertEquals(16, server.lastNonce().length);
    }

    @Test
    void wrongPasswordFailsWithoutThrowing() {
        assertFalse(ChimeraRuntime.authenticate(MockLicenseServer.ACCOUNT, "wrong", MockLicenseServer.HWID));
        assertFalse(ChimeraRuntime.isKeyHealthy(), "failed activation must poison the runtime");
    }

    @Test
    void tamperedSignatureFailsClosed() {
        // B1: nativeVerifyAuth returns a handle for every path; a canary check decides success.
        // A 32-byte poison key can no longer be installed as if it were valid (no fail-open).
        server.setTamperSignature(true);
        assertFalse(ChimeraRuntime.authenticate(MockLicenseServer.ACCOUNT,
                MockLicenseServer.PASSWORD, MockLicenseServer.HWID));
        assertFalse(ChimeraRuntime.isKeyHealthy(),
                "tampered signature must not install a usable session");
        assertTrue(ChimeraRuntime.nativeAuthAvailable());
    }

    @Test
    void heartbeatRotatesNonceAndKeepsSessionHealthy() {
        assertTrue(ChimeraRuntime.authenticate(MockLicenseServer.ACCOUNT,
                MockLicenseServer.PASSWORD, MockLicenseServer.HWID));
        byte[] firstNonce = server.lastNonce();
        long firstEpoch = ChimeraRuntime.sessionEpoch();
        assertTrue(ChimeraRuntime.heartbeatNow(), "heartbeat must succeed for a valid token");
        byte[] secondNonce = server.lastNonce();
        assertFalse(Arrays.equals(firstNonce, secondNonce), "server must rotate the nonce");
        assertNotEquals(firstEpoch, ChimeraRuntime.sessionEpoch(), "nonce update must bump the epoch");
        assertTrue(ChimeraRuntime.isKeyHealthy());
    }

    @Test
    void unreachableServerDegradesWithoutThrowing() {
        System.setProperty("chimera.auth.server", "http://127.0.0.1:1");
        assertFalse(ChimeraRuntime.authenticate(MockLicenseServer.ACCOUNT,
                MockLicenseServer.PASSWORD, MockLicenseServer.HWID));
        assertFalse(ChimeraRuntime.isKeyHealthy());
    }

    @Test
    void replayedHeartbeatPoisonsSession() {
        assertTrue(ChimeraRuntime.authenticate(MockLicenseServer.ACCOUNT,
                MockLicenseServer.PASSWORD, MockLicenseServer.HWID));
        assertTrue(ChimeraRuntime.heartbeatNow(), "first heartbeat issues sequence 2");
        long sequence = server.currentSequence();
        server.setReplayOldHeartbeat(true);
        assertFalse(ChimeraRuntime.heartbeatNow(), "stale sequence must be rejected");
        assertFalse(ChimeraRuntime.isKeyHealthy(),
                "a replayed/rolled-back heartbeat must poison the session");
        assertEquals(sequence, server.currentSequence(), "replay must not advance the server sequence");
    }

    // ------------------------------------------------------------------ B7-pre/KI-26 retry path

    @Test
    void expiredHandleReauthenticatesInsteadOfSurfacingABusinessFailure() {
        assertTrue(ChimeraRuntime.authenticate(MockLicenseServer.ACCOUNT,
                MockLicenseServer.PASSWORD, MockLicenseServer.HWID));
        assertEquals(1, server.activations());
        assertEquals(1L, ChimeraRuntime.handleCanaryForTest(), "activation installs a usable handle");

        assertTrue(ChimeraRuntime.expireHandleForTest(), "QA hook must expire the live handle");
        assertEquals(0L, ChimeraRuntime.handleCanaryForTest(), "expired handle is unusable");

        assertTrue(ChimeraRuntime.ensureSessionHealthy(),
                "the Java layer must re-activate instead of failing business logic");
        assertEquals(2, server.activations(), "exactly one re-activation for one expiry");
        assertTrue(ChimeraRuntime.isKeyHealthy(), "runtime must stay healthy after the retry");
        assertEquals(1L, ChimeraRuntime.handleCanaryForTest(), "retry installs a fresh handle");
    }

    @Test
    void realTtlExpiryTriggersReauthentication() throws Exception {
        Assumptions.assumeTrue(ChimeraRuntime.isDevNativeBuild(),
                "real-wait TTL test requires the dev DLL with a 1 s floor");
        long originalTtl = ChimeraRuntime.handleTtlMs();
        try {
            assertEquals(1_000L, ChimeraRuntime.setHandleTtlMsForTest(1_000L));
            assertTrue(ChimeraRuntime.authenticate(MockLicenseServer.ACCOUNT,
                    MockLicenseServer.PASSWORD, MockLicenseServer.HWID));
            assertEquals(1L, ChimeraRuntime.handleCanaryForTest());
            Thread.sleep(1_500L);
            assertEquals(0L, ChimeraRuntime.handleCanaryForTest(),
                    "real wall-clock TTL wait must expire the handle");
            assertTrue(ChimeraRuntime.ensureSessionHealthy(),
                    "expired handle must trigger re-authentication");
            assertEquals(2, server.activations());
            assertTrue(ChimeraRuntime.isKeyHealthy());
        } finally {
            ChimeraRuntime.setHandleTtlMsForTest(originalTtl);
        }
    }

    @Test
    void repeatedReconnectsDoNotRotateAHealthySession() {
        for (int i = 0; i < 20; i++) {
            assertTrue(ChimeraRuntime.authenticate(MockLicenseServer.ACCOUNT,
                    MockLicenseServer.PASSWORD, MockLicenseServer.HWID), "reconnect " + i);
            assertTrue(ChimeraRuntime.isKeyHealthy());
        }
        assertEquals(20, server.activations());
        assertTrue(ChimeraRuntime.ensureSessionHealthy(),
                "the latest handle must remain valid after 20 reconnects");
        assertEquals(20, server.activations(),
                "a healthy handle must not trigger another activation");
    }

    @Test
    void revokedSessionFailsClosedWithoutThrowing() {
        assertTrue(ChimeraRuntime.authenticate(MockLicenseServer.ACCOUNT,
                MockLicenseServer.PASSWORD, MockLicenseServer.HWID));
        assertDoesNotThrow(ChimeraRuntime::revokeSession);
        assertFalse(ChimeraRuntime.isKeyHealthy(), "logout must poison the business values");
        assertFalse(ChimeraRuntime.ensureSessionHealthy(),
                "revoked credentials are cleared; no silent re-activation");
    }

    @Test
    void heartbeatRejectsTamperedResponse() {
        assertTrue(ChimeraRuntime.authenticate(MockLicenseServer.ACCOUNT,
                MockLicenseServer.PASSWORD, MockLicenseServer.HWID));
        server.setTamperSignature(true);
        assertFalse(ChimeraRuntime.heartbeatNow(), "tampered heartbeat signature must be rejected");
        assertTrue(ChimeraRuntime.isKeyHealthy(), "a failed heartbeat alone does not poison (retry budget)");
    }
}
