package dev.chimera.license;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.chimera.license.crypto.CryptoUtils;
import dev.chimera.license.service.RateLimiter;
import dev.chimera.license.service.RiskControlService;
import dev.chimera.license.store.LicenseStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Real HTTP tests for the v4 endpoints:
 * {@code POST /api/v1/license/v4/activate} and {@code POST /api/v1/license/v4/heartbeat}.
 *
 * <p>Every signature is verified with {@link TestClientCryptoV4}, an independent length-prefixed
 * canonical encoder, so the server's transcript is proven byte-compatible with the client contract
 * rather than self-consistent with the server encoder.</p>
 */
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:chimera-v4-test;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.sql.init.mode=always",
        "license.key-dir=build/test-keys-v4",
        "license.content-key-hex=" + TestClientCrypto.MASTER_KEY_HEX,
        "license.resource-key-hex=" + TestClientCrypto.RESOURCE_KEY_HEX,
        "license.session-ttl-seconds=3600",
        "license.rate-limit.max-failures=3",
        "license.risk-control.window-seconds=60",
        "license.risk-control.poison-ttl-seconds=60"
})
@AutoConfigureMockMvc
@Import(LicenseV4ApiTest.ClockConfig.class)
class LicenseV4ApiTest {

    private static final String ACTIVATE = "/api/v1/license/v4/activate";
    private static final String HEARTBEAT = "/api/v1/license/v4/heartbeat";
    private static final String ACCOUNT = "v4-account";
    private static final String PASSWORD = "v4-password";
    private static final String HWID = "hwid-v4-0001";
    private static final long NOW = 1_760_000_000L;
    private static final long TTL = 3600L;

    @TestConfiguration
    static class ClockConfig {

        @Bean
        @Primary
        MutableClock v4TestClock() {
            return new MutableClock(NOW);
        }
    }

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper json;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private LicenseStore store;

    @Autowired
    private RateLimiter rateLimiter;

    @Autowired
    private RiskControlService riskControl;

    @Autowired
    private MutableClock clock;

    @BeforeEach
    void resetState() {
        clock.setEpochSecond(NOW);
        LicenseStore.AccountRow row = store.findAccount(ACCOUNT).orElse(null);
        if (row == null) {
            store.insertAccount(ACCOUNT, CryptoUtils.hashPassword(PASSWORD), "ACTIVE");
            row = store.findAccount(ACCOUNT).orElseThrow();
        } else {
            // A previous test may have banned the account (heartbeatStopsWhenTheAccountIsBanned);
            // the row survives because the fixture is shared, so normalise the status here.
            jdbc.update("UPDATE accounts SET status = 'ACTIVE' WHERE account = ?", ACCOUNT);
        }
        store.deleteDevices(row.id());
        jdbc.update("DELETE FROM auth_v4_sessions");
        jdbc.update("DELETE FROM auth_v4_nonces");
        jdbc.update("DELETE FROM auth_v4_sequences");
        jdbc.update("DELETE FROM auth_v4_tokens");
        rateLimiter.reset(ACCOUNT + "|127.0.0.1");
        riskControl.reset();
    }

    // ---------------------------------------------------------------- happy paths

    @Test
    void activateStartsAtSequenceOneAndBindsRequestFields() throws Exception {
        KeyPair client = CryptoUtils.x25519KeyPair();
        String nonce = newNonce();
        JsonNode node = activateOk(client, nonce);

        assertEquals(4, node.get("v").asInt());
        assertEquals(ACCOUNT, node.get("account").asText());
        assertEquals(HWID, node.get("hwid").asText());
        assertEquals(clientPublicBase64(client), node.get("client_ephemeral_pub").asText());
        assertEquals(nonce, node.get("client_nonce").asText());
        assertEquals(1L, node.get("sequence").asLong(), "activation sequence must start at 1");
        assertEquals(NOW, node.get("issued_at").asLong());
        assertEquals(NOW, node.get("server_time").asLong());
        assertEquals(NOW + TTL, node.get("expires_at").asLong());
        assertEquals(24, node.get("server_nonce").asText().length(), "server_nonce is 16B base64");
        assertEquals(44, node.get("token").asText().length(), "token is 32B base64");
        assertEquals(80, node.get("resource_ck").asText().length(),
                "resource_ck is 60B AES-GCM envelope");
        assertTrue(TestClientCryptoV4.verifyActivate(node, serverPublicKey()),
                "activation signature must verify with the independent client encoder");
    }

    /**
     * Red team round 3, finding 3: the account used to be bound on the {@code hwid} string alone,
     * so anyone who learned a customer's 64 hex could activate on another machine. The identity is
     * now the DPAPI-sealed client key, and a different key presenting the same string is refused.
     */
    @Test
    void activateRejectsACopiedHwidWithADifferentDeviceKey() throws Exception {
        KeyPair victim = CryptoUtils.x25519KeyPair();
        activateOk(victim, newNonce());

        KeyPair attacker = CryptoUtils.x25519KeyPair();
        MvcResult result = postActivate(activateBody(4, newNonce(), attacker));
        assertEquals(403, result.getResponse().getStatus(),
                result.getResponse().getContentAsString());
        assertEquals("E_DEVICE_KEY_MISMATCH", error(result));
    }

    /**
     * Red team round 4 (source audit): the device limit was a read-then-write, so N machines
     * activating the same account simultaneously all saw zero devices and all bound. A customer
     * with a shell could therefore multiply their device allowance without support.
     */
    @Test
    void concurrentActivationsCannotExceedTheDeviceLimit() throws Exception {
        final int threads = 6;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Integer>> results = new ArrayList<>();
        try {
            for (int i = 0; i < threads; i++) {
                final String hwid = String.format("%064x", i + 1);
                final KeyPair client = CryptoUtils.x25519KeyPair();
                results.add(pool.submit(() -> {
                    start.await();
                    return postActivate(activateBody(4, newNonce(), client, hwid))
                            .getResponse().getStatus();
                }));
            }
            start.countDown();
            int accepted = 0;
            for (Future<Integer> result : results) {
                if (result.get(30, TimeUnit.SECONDS) == 200) {
                    accepted++;
                }
            }
            assertEquals(1, accepted,
                    "exactly one device may bind; every other concurrent activation must be refused");
            assertEquals(1, store.devices(store.findAccount(ACCOUNT).orElseThrow().id()).size(),
                    "the account must end up with a single bound device");
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void sameDeviceKeyMayActivateAgain() throws Exception {
        KeyPair device = CryptoUtils.x25519KeyPair();
        activateOk(device, newNonce());
        clock.advanceSeconds(30);
        // Session expiry / restart on the same machine must keep working: the sealed key is stable,
        // so re-activation presents the same public key.
        activateOk(device, newNonce());
    }

    /**
     * Upgrade path: rows bound before {@code device_pub} existed carry NULL. The first activation
     * after the upgrade adopts the presented key, so no already-bound customer is locked out.
     */
    @Test
    void legacyDeviceRowAdoptsThePresentedKeyOnce() throws Exception {
        LicenseStore.AccountRow row = store.findAccount(ACCOUNT).orElseThrow();
        jdbc.update("INSERT INTO devices(account_id, hwid, label, first_seen, last_seen, status) "
                        + "VALUES (?,?,?,?,?,'ACTIVE')",
                row.id(), HWID, "legacy", java.sql.Timestamp.from(java.time.Instant.ofEpochSecond(NOW)),
                java.sql.Timestamp.from(java.time.Instant.ofEpochSecond(NOW)));

        KeyPair device = CryptoUtils.x25519KeyPair();
        activateOk(device, newNonce());

        // Adopted, so a different key is now refused on that same legacy row.
        MvcResult result = postActivate(activateBody(4, newNonce(), CryptoUtils.x25519KeyPair()));
        assertEquals(403, result.getResponse().getStatus());
        assertEquals("E_DEVICE_KEY_MISMATCH", error(result));
    }

    /**
     * Red team round 4 (source audit): heartbeat used to validate the session row only and to slide
     * {@code expires_at} forward on every renewal, so a banned account kept playing forever.
     */
    @Test
    void heartbeatStopsWhenTheAccountIsBanned() throws Exception {
        KeyPair client = CryptoUtils.x25519KeyPair();
        String token = activateOk(client, newNonce()).get("token").asText();

        jdbc.update("UPDATE accounts SET status = 'BANNED' WHERE account = ?", ACCOUNT);

        MvcResult result = postHeartbeat(heartbeatBody(token, newNonce(), 1L, client));
        assertEquals(403, result.getResponse().getStatus(),
                result.getResponse().getContentAsString());
        assertEquals("E_REVOKED", error(result));
    }

    /**
     * Same finding, second half: {@code /admin/rebind} cleared the device rows but left the live
     * session renewing itself, so the machine support just "unbound" stayed online.
     */
    @Test
    void heartbeatStopsWhenTheDeviceBindingIsCleared() throws Exception {
        KeyPair client = CryptoUtils.x25519KeyPair();
        String token = activateOk(client, newNonce()).get("token").asText();

        store.deleteDevices(store.findAccount(ACCOUNT).orElseThrow().id());

        MvcResult result = postHeartbeat(heartbeatBody(token, newNonce(), 1L, client));
        assertEquals(403, result.getResponse().getStatus(),
                result.getResponse().getContentAsString());
        assertEquals("E_BINDING", error(result));
    }

    @Test
    void heartbeatRotatesTokenNonceAndSequence() throws Exception {
        KeyPair client = CryptoUtils.x25519KeyPair();
        JsonNode activated = activateOk(client, newNonce());
        String oldToken = activated.get("token").asText();
        String oldNonce = activated.get("server_nonce").asText();

        clock.advanceSeconds(10);
        String nonce = newNonce();
        JsonNode first = heartbeatOk(oldToken, nonce, 1L, client);

        assertEquals(4, first.get("v").asInt());
        assertEquals(HWID, first.get("hwid").asText());
        assertEquals(nonce, first.get("client_nonce").asText());
        assertEquals(2L, first.get("sequence").asLong(), "heartbeat sequence = request + 1");
        assertNotEquals(oldToken, first.get("token").asText(), "token must rotate");
        assertNotEquals(oldNonce, first.get("server_nonce").asText(),
                "server_nonce must be fresh");
        assertEquals(NOW + 10, first.get("issued_at").asLong());
        assertEquals(NOW + 10, first.get("server_time").asLong());
        assertEquals(NOW + 10 + TTL, first.get("expires_at").asLong());
        assertTrue(TestClientCryptoV4.verifyHeartbeat(first, oldToken, serverPublicKey()),
                "heartbeat signature must bind the presented (old) token hash");
        String canonicalText = new String(
                TestClientCryptoV4.canonicalHeartbeat(first, oldToken),
                StandardCharsets.ISO_8859_1);
        assertTrue(canonicalText.contains(TestClientCryptoV4.tokenHashHex(oldToken)),
                "canonical must contain SHA256hex(presented token)");

        String rotated = first.get("token").asText();
        clock.advanceSeconds(10);
        JsonNode second = heartbeatOk(rotated, newNonce(), 2L, client);
        assertEquals(3L, second.get("sequence").asLong());
        assertNotEquals(rotated, second.get("token").asText(), "every heartbeat rotates the token");
        assertNotEquals(first.get("server_nonce").asText(), second.get("server_nonce").asText());
        assertTrue(TestClientCryptoV4.verifyHeartbeat(second, rotated, serverPublicKey()));
    }

    // ---------------------------------------------------------------- negative paths

    @Test
    void activateRejectsUnknownVersion() throws Exception {
        Map<String, Object> body = activateBody(3, newNonce(), CryptoUtils.x25519KeyPair());
        MvcResult result = postActivate(body);
        assertEquals(400, result.getResponse().getStatus());
        assertEquals("E_VERSION", error(result));
    }

    @Test
    void activateRejectsReplayedClientNonce() throws Exception {
        // A replay resends the *identical* request, so it carries the same device key. (Presenting a
        // different key with the same nonce is caught earlier now, as E_DEVICE_KEY_MISMATCH.)
        KeyPair device = CryptoUtils.x25519KeyPair();
        String nonce = newNonce();
        activateOk(device, nonce);

        MvcResult replay = postActivate(activateBody(4, nonce, device));
        assertEquals(409, replay.getResponse().getStatus());
        assertEquals("E_REPLAY", error(replay));
    }

    @Test
    void heartbeatRejectsExpiredSession() throws Exception {
        KeyPair client = CryptoUtils.x25519KeyPair();
        JsonNode activated = activateOk(client, newNonce());
        String token = activated.get("token").asText();
        jdbc.update("UPDATE auth_v4_sessions SET expires_at = ? WHERE token = ?",
                NOW - 1, token);

        MvcResult result = postHeartbeat(heartbeatBody(token, newNonce(), 1L, client));
        assertEquals(410, result.getResponse().getStatus());
        assertEquals("E_EXPIRED", error(result));
    }

    @Test
    void expiryTakesPriorityOverClockRollback() throws Exception {
        KeyPair client = CryptoUtils.x25519KeyPair();
        JsonNode activated = activateOk(client, newNonce());
        String token = activated.get("token").asText();
        jdbc.update("UPDATE auth_v4_sessions SET issued_at = ?, expires_at = ? WHERE token = ?",
                NOW + 100, NOW - 1, token);

        MvcResult result = postHeartbeat(heartbeatBody(token, newNonce(), 1L, client));
        assertEquals(410, result.getResponse().getStatus(),
                "an already-expired session must report E_EXPIRED, not E_CLOCK_ROLLBACK");
        assertEquals("E_EXPIRED", error(result));
    }

    @Test
    void heartbeatRejectsClockRollback() throws Exception {
        KeyPair client = CryptoUtils.x25519KeyPair();
        JsonNode activated = activateOk(client, newNonce());
        String token = activated.get("token").asText();
        jdbc.update("UPDATE auth_v4_sessions SET issued_at = ? WHERE token = ?",
                NOW + 120, token);

        MvcResult result = postHeartbeat(heartbeatBody(token, newNonce(), 1L, client));
        assertEquals(409, result.getResponse().getStatus());
        assertEquals("E_CLOCK_ROLLBACK", error(result));
    }

    @Test
    void heartbeatRejectsReusedOldToken() throws Exception {
        KeyPair client = CryptoUtils.x25519KeyPair();
        JsonNode activated = activateOk(client, newNonce());
        String oldToken = activated.get("token").asText();
        heartbeatOk(oldToken, newNonce(), 1L, client);

        MvcResult result = postHeartbeat(heartbeatBody(oldToken, newNonce(), 2L, client));
        assertEquals(403, result.getResponse().getStatus(),
                "the rotated-away token must stop resolving");
        assertEquals("E_REVOKED", error(result));
    }

    @Test
    void heartbeatRejectsSequenceRollback() throws Exception {
        KeyPair client = CryptoUtils.x25519KeyPair();
        JsonNode activated = activateOk(client, newNonce());
        String oldToken = activated.get("token").asText();
        String newToken = heartbeatOk(oldToken, newNonce(), 1L, client).get("token").asText();

        MvcResult result = postHeartbeat(heartbeatBody(newToken, newNonce(), 1L, client));
        assertEquals(409, result.getResponse().getStatus());
        assertEquals("E_SEQUENCE", error(result));
    }

    @Test
    void heartbeatRejectsReplayedClientNonce() throws Exception {
        KeyPair client = CryptoUtils.x25519KeyPair();
        JsonNode activated = activateOk(client, newNonce());
        String oldToken = activated.get("token").asText();
        String nonce = newNonce();
        JsonNode first = heartbeatOk(oldToken, nonce, 1L, client);

        MvcResult replay = postHeartbeat(
                heartbeatBody(first.get("token").asText(), nonce, 2L, client));
        assertEquals(409, replay.getResponse().getStatus());
        assertEquals("E_REPLAY", error(replay));
    }

    /**
     * Core acceptance test of the client-key binding: a valid bearer token presented together with
     * a different (attacker-controlled) X25519 key must be rejected with {@code E_KEY_MISMATCH},
     * because the ResourceKey would otherwise be wrapped to that key. The rejection happens before
     * any state mutation, so the legitimate client can still heartbeat with the same nonce.
     */
    @Test
    void heartbeatWithRotatedClientKeyIsRejected() throws Exception {
        KeyPair client = CryptoUtils.x25519KeyPair();
        JsonNode activated = activateOk(client, newNonce());
        String token = activated.get("token").asText();

        KeyPair attacker = CryptoUtils.x25519KeyPair();
        String nonce = newNonce();
        MvcResult hijack = postHeartbeat(heartbeatBody(token, nonce, 1L, attacker));
        assertEquals(403, hijack.getResponse().getStatus(),
                "a heartbeat signed by a different client key must be refused");
        assertEquals("E_KEY_MISMATCH", error(hijack));

        // No rotation, no consumed nonce/sequence: the bound key still works and the token did
        // not move, which proves the mismatch check runs before any session mutation.
        MvcResult legitimate = postHeartbeat(heartbeatBody(token, nonce, 1L, client));
        assertEquals(200, legitimate.getResponse().getStatus(),
                legitimate.getResponse().getContentAsString());
        JsonNode rotated = json.readTree(legitimate.getResponse().getContentAsString());
        assertEquals(2L, rotated.get("sequence").asLong());
        assertNotEquals(token, rotated.get("token").asText());
        assertTrue(TestClientCryptoV4.verifyHeartbeat(rotated, token, serverPublicKey()));
    }

    @Test
    void tamperedActivateFieldAndSignatureFailVerification() throws Exception {
        JsonNode node = activateOk(CryptoUtils.x25519KeyPair(), newNonce());
        PublicKey publicKey = serverPublicKey();
        assertTrue(TestClientCryptoV4.verifyActivate(node, publicKey));

        ObjectNode changedField = node.deepCopy();
        changedField.put("account", "evil@example.com");
        assertFalse(TestClientCryptoV4.verifyActivate(changedField, publicKey),
                "a changed response field must invalidate the signature");

        ObjectNode changedSignature = node.deepCopy();
        byte[] signature = Base64.getDecoder().decode(node.get("signature").asText());
        signature[signature.length - 1] ^= 0x01;
        changedSignature.put("signature", Base64.getEncoder().encodeToString(signature));
        assertFalse(TestClientCryptoV4.verifyActivate(changedSignature, publicKey),
                "a tampered signature must not verify");
    }

    @Test
    void tamperedHeartbeatFieldAndSignatureFailVerification() throws Exception {
        KeyPair client = CryptoUtils.x25519KeyPair();
        JsonNode activated = activateOk(client, newNonce());
        String oldToken = activated.get("token").asText();
        JsonNode heartbeat = heartbeatOk(oldToken, newNonce(), 1L, client);
        PublicKey publicKey = serverPublicKey();
        assertTrue(TestClientCryptoV4.verifyHeartbeat(heartbeat, oldToken, publicKey));

        ObjectNode changedSequence = heartbeat.deepCopy();
        changedSequence.put("sequence", 3L);
        assertFalse(TestClientCryptoV4.verifyHeartbeat(changedSequence, oldToken, publicKey));

        ObjectNode changedSignature = heartbeat.deepCopy();
        byte[] signature = Base64.getDecoder().decode(heartbeat.get("signature").asText());
        signature[0] ^= 0x01;
        changedSignature.put("signature", Base64.getEncoder().encodeToString(signature));
        assertFalse(TestClientCryptoV4.verifyHeartbeat(changedSignature, oldToken, publicKey));
    }

    /**
     * The v3 endpoints were deleted (2026-10-22): v3 heartbeat authenticated with a bearer token
     * only, so a leaked token could be renewed forever. This test used to assert that v3 stayed
     * compatible; under the new contract the assertion is inverted - the paths must be gone -
     * while the v4 replacement is still proven end to end in the same test.
     */
    @Test
    void v3EndpointsAreGone() throws Exception {
        KeyPair client = CryptoUtils.x25519KeyPair();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("account", ACCOUNT);
        body.put("password", PASSWORD);
        body.put("hwid", HWID);
        body.put("client_ephemeral_pub", clientPublicBase64(client));

        MvcResult v3Activate = mvc.perform(post("/api/v1/license/activate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(body)))
                .andReturn();
        assertEquals(404, v3Activate.getResponse().getStatus(),
                "POST /api/v1/license/activate must no longer exist: "
                        + v3Activate.getResponse().getContentAsString());
        assertEquals("E_NOT_FOUND", error(v3Activate));

        MvcResult v3Heartbeat = mvc.perform(post("/api/v1/license/heartbeat")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("token", "any-token"))))
                .andReturn();
        assertEquals(404, v3Heartbeat.getResponse().getStatus(),
                "POST /api/v1/license/heartbeat must no longer exist: "
                        + v3Heartbeat.getResponse().getContentAsString());
        assertEquals("E_NOT_FOUND", error(v3Heartbeat));

        // The v4 endpoints that replaced them still serve the full flow.
        JsonNode activated = activateOk(client, newNonce());
        PublicKey publicKey = serverPublicKey();
        assertTrue(TestClientCryptoV4.verifyActivate(activated, publicKey),
                "v4 activation must still be signed and verifiable");
        String token = activated.get("token").asText();
        JsonNode heartbeat = heartbeatOk(token, newNonce(), 1L, client);
        assertTrue(TestClientCryptoV4.verifyHeartbeat(heartbeat, token, publicKey),
                "v4 heartbeat must still be signed and verifiable");
    }

    // ---------------------------------------------------------------- helpers

    private Map<String, Object> activateBody(int version, String nonce, KeyPair client) {
        return activateBody(version, nonce, client, HWID);
    }

    private Map<String, Object> activateBody(int version, String nonce, KeyPair client,
                                             String hwid) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("v", version);
        body.put("account", ACCOUNT);
        body.put("password", PASSWORD);
        body.put("hwid", hwid);
        body.put("client_ephemeral_pub", clientPublicBase64(client));
        body.put("client_nonce", nonce);
        return body;
    }

    private Map<String, Object> heartbeatBody(String token, String nonce, long sequence,
                                              KeyPair client) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("v", 4);
        body.put("hwid", HWID);
        body.put("token", token);
        body.put("client_nonce", nonce);
        body.put("sequence", sequence);
        // The session is bound to the X25519 key presented at activation, so a heartbeat must
        // present that same key (E_KEY_MISMATCH otherwise).
        body.put("client_ephemeral_pub", clientPublicBase64(client));
        return body;
    }

    private MvcResult postActivate(Map<String, Object> body) throws Exception {
        return mvc.perform(post(ACTIVATE)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(body)))
                .andReturn();
    }

    private MvcResult postHeartbeat(Map<String, Object> body) throws Exception {
        return mvc.perform(post(HEARTBEAT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(body)))
                .andReturn();
    }

    private JsonNode activateOk(KeyPair client, String nonce) throws Exception {
        MvcResult result = postActivate(activateBody(4, nonce, client));
        assertEquals(200, result.getResponse().getStatus(), result.getResponse().getContentAsString());
        return json.readTree(result.getResponse().getContentAsString());
    }

    private JsonNode heartbeatOk(String token, String nonce, long sequence, KeyPair client)
            throws Exception {
        MvcResult result = postHeartbeat(heartbeatBody(token, nonce, sequence, client));
        assertEquals(200, result.getResponse().getStatus(), result.getResponse().getContentAsString());
        return json.readTree(result.getResponse().getContentAsString());
    }

    private String error(MvcResult result) throws Exception {
        return json.readTree(result.getResponse().getContentAsString()).get("error").asText();
    }

    private PublicKey serverPublicKey() throws Exception {
        MvcResult result = mvc.perform(get("/api/v1/license/pubkey")).andReturn();
        assertEquals(200, result.getResponse().getStatus());
        String raw = json.readTree(result.getResponse().getContentAsString())
                .get("pubkey").asText();
        return TestClientCryptoV4.ed25519PublicKey(Base64.getDecoder().decode(raw));
    }

    private static String clientPublicBase64(KeyPair client) {
        return Base64.getEncoder().encodeToString(CryptoUtils.rawX25519(client.getPublic()));
    }

    private static String newNonce() {
        return Base64.getEncoder().encodeToString(CryptoUtils.random(32));
    }
}
