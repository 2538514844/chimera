package dev.chimera.license;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.chimera.license.crypto.CryptoUtils;
import dev.chimera.license.service.RateLimiter;
import dev.chimera.license.service.RiskControlService;
import dev.chimera.license.store.LicenseStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import javax.crypto.AEADBadTagException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * B-Full lite (server side) + risk-control tests against the <b>v4</b> wire protocol.
 *
 * <ul>
 *   <li>HWID_A receives the correctly wrapped ResourceKey and can decrypt paid content.</li>
 *   <li>HWID_B, activated by the same account within the risk window, receives a signed but
 *       byte-rotated (poisoned) ResourceKey and cannot decrypt HWID_A's content.</li>
 *   <li>the poison flag is scoped per device and is honoured on the heartbeat re-delivery.</li>
 * </ul>
 *
 * <p>Semantics changed with the 2026-10-22 v4 hardening: v3 delivered a per-device derived
 * {@code UserContentKey} in {@code wrapped_ck} and then wrapped the ResourceKey under it. v4
 * removes {@code wrapped_ck} entirely and wraps the ResourceKey directly to the X25519 key
 * presented at activation (ECDH + HKDF, AAD bound to account/hwid), so these tests assert the
 * ResourceKey envelope instead of a derived UserContentKey.</p>
 *
 * <p>Tests run with {@code max-devices-per-account=2} because the default 1:1 device policy
 * rejects a second HWID before any payload exists; see docs/known-issues.md KI-28.</p>
 */
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:chimera-risk-test;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.sql.init.mode=always",
        "license.key-dir=build/test-keys-risk",
        "license.content-key-hex=" + TestClientCrypto.MASTER_KEY_HEX,
        "license.resource-key-hex=" + TestClientCrypto.RESOURCE_KEY_HEX,
        "license.max-devices-per-account=2",
        "license.auto-bind-first-device=true",
        "license.session-ttl-seconds=3600",
        "license.risk-control.window-seconds=60",
        "license.risk-control.poison-ttl-seconds=60",
        "license.rate-limit.max-failures=100"
})
@AutoConfigureMockMvc
class RiskControlIntegrationTest {

    private static final String ACTIVATE = "/api/v1/license/v4/activate";
    private static final String HEARTBEAT = "/api/v1/license/v4/heartbeat";
    private static final String ACCOUNT = "risk-account";
    private static final String PASSWORD = "risk-password";
    private static final String HWID_A = "risk-hwid-A";
    private static final String HWID_B = "risk-hwid-B";

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper json;

    @Autowired
    private LicenseStore store;

    @Autowired
    private RateLimiter rateLimiter;

    @Autowired
    private RiskControlService riskControl;

    @Autowired
    private JdbcTemplate jdbc;

    @BeforeEach
    void cleanState() {
        LicenseStore.AccountRow row = store.findAccount(ACCOUNT).orElse(null);
        if (row == null) {
            store.insertAccount(ACCOUNT, CryptoUtils.hashPassword(PASSWORD), "ACTIVE");
            row = store.findAccount(ACCOUNT).orElseThrow();
        }
        store.deleteDevices(row.id());
        jdbc.update("DELETE FROM auth_v4_sessions");
        jdbc.update("DELETE FROM auth_v4_nonces");
        jdbc.update("DELETE FROM auth_v4_sequences");
        jdbc.update("DELETE FROM auth_v4_tokens");
        jdbc.update("DELETE FROM audit_logs");
        rateLimiter.reset(ACCOUNT + "|127.0.0.1");
        riskControl.reset();
    }

    private JsonNode activateOk(String hwid, KeyPair client) throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("v", 4);
        body.put("account", ACCOUNT);
        body.put("password", PASSWORD);
        body.put("hwid", hwid);
        body.put("client_ephemeral_pub",
                TestClientCrypto.b64(CryptoUtils.rawX25519(client.getPublic())));
        body.put("client_nonce", TestClientCrypto.b64(CryptoUtils.random(32)));
        MvcResult result = mvc.perform(post(ACTIVATE)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(body)))
                .andReturn();
        assertEquals(200, result.getResponse().getStatus(), result.getResponse().getContentAsString());
        return json.readTree(result.getResponse().getContentAsString());
    }

    private JsonNode heartbeatOk(String hwid, String token, long sequence, KeyPair client)
            throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("v", 4);
        body.put("hwid", hwid);
        body.put("token", token);
        body.put("client_nonce", TestClientCrypto.b64(CryptoUtils.random(32)));
        body.put("sequence", sequence);
        body.put("client_ephemeral_pub",
                TestClientCrypto.b64(CryptoUtils.rawX25519(client.getPublic())));
        MvcResult result = mvc.perform(post(HEARTBEAT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(body)))
                .andReturn();
        assertEquals(200, result.getResponse().getStatus(), result.getResponse().getContentAsString());
        return json.readTree(result.getResponse().getContentAsString());
    }

    private PublicKey serverSigningKey() throws Exception {
        MvcResult result = mvc.perform(get("/api/v1/license/pubkey")).andReturn();
        assertEquals(200, result.getResponse().getStatus());
        String pubkey = json.readTree(result.getResponse().getContentAsString()).get("pubkey").asText();
        return TestClientCrypto.ed25519PublicKey(Base64.getDecoder().decode(pubkey));
    }

    /** Unwraps the v4 ECDH-wrapped ResourceKey with the client key used for that request. */
    private byte[] unwrap(KeyPair client, JsonNode node, String hwid) throws Exception {
        return TestClientCryptoV4.unpackResourceKey(client.getPrivate(),
                node.get("client_nonce").asText(),
                node.get("server_ephemeral_pub").asText(),
                node.get("resource_ck").asText(),
                ACCOUNT, hwid);
    }

    @Test
    void firstDeviceGetsResourceKeyAndStableDerivation() throws Exception {
        KeyPair client = CryptoUtils.x25519KeyPair();
        JsonNode first = activateOk(HWID_A, client);
        assertTrue(TestClientCryptoV4.verifyActivate(first, serverSigningKey()));

        byte[] key = unwrap(client, first, HWID_A);
        assertEquals(32, key.length);
        assertArrayEquals(TestClientCrypto.resourceKey(), key,
                "HWID_A must decrypt the signed envelope to the configured ResourceKey");
        assertFalse(Arrays.equals(TestClientCrypto.masterKey(), key),
                "the MasterKey itself must never be delivered to clients");

        // Re-activation on the same machine presents the same device key (it is DPAPI-sealed and
        // generated once), and must deliver the same account-wide ResourceKey through a fresh
        // envelope. A *different* key on the same HWID is now refused - see
        // LicenseV4ApiTest#activateRejectsACopiedHwidWithADifferentDeviceKey.
        JsonNode second = activateOk(HWID_A, client);
        assertTrue(TestClientCryptoV4.verifyActivate(second, serverSigningKey()));
        byte[] keyAgain = unwrap(client, second, HWID_A);
        assertArrayEquals(key, keyAgain,
                "re-activation of the same device must deliver the same ResourceKey");
        assertNotEquals(first.get("resource_ck").asText(), second.get("resource_ck").asText(),
                "every activation re-wraps the ResourceKey with a fresh server ephemeral key");
        KeyPair stranger = CryptoUtils.x25519KeyPair();
        assertThrows(AEADBadTagException.class, () -> unwrap(stranger, second, HWID_A),
                "an envelope is bound to the client key of its own activation");
    }

    @Test
    void secondDeviceWithinWindowGetsSignedButPoisonedKey() throws Exception {
        KeyPair clientA = CryptoUtils.x25519KeyPair();
        KeyPair clientB = CryptoUtils.x25519KeyPair();

        JsonNode nodeA = activateOk(HWID_A, clientA);
        JsonNode nodeB = activateOk(HWID_B, clientB);

        assertTrue(TestClientCryptoV4.verifyActivate(nodeA, serverSigningKey()));
        assertTrue(TestClientCryptoV4.verifyActivate(nodeB, serverSigningKey()),
                "poisoned payload must still carry a valid signature");

        byte[] keyA = unwrap(clientA, nodeA, HWID_A);
        assertArrayEquals(TestClientCrypto.resourceKey(), keyA, "first device keeps the correct key");

        byte[] keyB = unwrap(clientB, nodeB, HWID_B);
        assertArrayEquals(TestClientCrypto.poisonResourceKey(TestClientCrypto.resourceKey()), keyB,
                "the rapid-switch device receives the byte-rotated ResourceKey");
        assertFalse(Arrays.equals(TestClientCrypto.resourceKey(), keyB));
        assertEquals(80, nodeB.get("resource_ck").asText().length(),
                "poisoned payload keeps the normal wire shape (60 bytes / 80 base64 chars)");

        Integer poisonedAudits = jdbc.queryForObject(
                "SELECT COUNT(*) FROM audit_logs WHERE event = 'ACTIVATE_V4_POISONED'", Integer.class);
        assertEquals(1, poisonedAudits, "risk-control decision must be audited");
    }

    @Test
    void crossMachinePayloadCannotDecryptContentOrBeReplayed() throws Exception {
        KeyPair clientA = CryptoUtils.x25519KeyPair();
        KeyPair clientB = CryptoUtils.x25519KeyPair();
        JsonNode nodeA = activateOk(HWID_A, clientA);
        JsonNode nodeB = activateOk(HWID_B, clientB);

        byte[] keyA = unwrap(clientA, nodeA, HWID_A);
        byte[] keyB = unwrap(clientB, nodeB, HWID_B);
        byte[] content = "paid-content-that-needs-the-right-key".getBytes(StandardCharsets.UTF_8);
        byte[] sealed = TestClientCrypto.sealContent(keyA, content);

        assertArrayEquals(content, TestClientCrypto.openContent(keyA, sealed),
                "device A decrypts its own content with the ResourceKey");
        assertThrows(AEADBadTagException.class, () -> TestClientCrypto.openContent(keyB, sealed),
                "device B's poisoned ResourceKey must not decrypt device A's content");

        assertThrows(AEADBadTagException.class, () -> unwrap(clientB, nodeA, HWID_A),
                "replaying device A's resource_ck to a new client fails (ECDH mismatch)");
        assertThrows(AEADBadTagException.class, () -> unwrap(clientA, nodeB, HWID_B),
                "device A cannot decrypt device B's poisoned resource_ck");
    }

    /**
     * Semantics changed: this test used to prove that a heartbeat-observed HWID switch armed
     * poisoning for that HWID's next activation. v4 {@code LicenseV4Service.heartbeat} only reads
     * the poison flag ({@code riskControl.isPoisoned}) and no longer calls
     * {@code riskControl.recordActivity}, so a heartbeat cannot arm poison any more (reported as a
     * gap; not asserted here). What still holds, and is what this test now verifies, is that the
     * poison flag armed at activation is honoured when the heartbeat re-delivers the ResourceKey,
     * and that it stays scoped to the anomalous device.
     */
    @Test
    void heartbeatHonoursPoisonFlagAndKeepsOtherDeviceClean() throws Exception {
        KeyPair clientA = CryptoUtils.x25519KeyPair();
        KeyPair clientB = CryptoUtils.x25519KeyPair();
        JsonNode nodeA = activateOk(HWID_A, clientA);
        JsonNode nodeB = activateOk(HWID_B, clientB);

        // Both devices of the same account heartbeat inside the risk window. Sequences are
        // per-session, so both sessions independently advance 1 -> 2.
        String tokenB = nodeB.get("token").asText();
        JsonNode heartbeatB = heartbeatOk(HWID_B, tokenB, 1L, clientB);
        assertTrue(TestClientCryptoV4.verifyHeartbeat(heartbeatB, tokenB, serverSigningKey()));
        assertEquals(2L, heartbeatB.get("sequence").asLong());

        String tokenA = nodeA.get("token").asText();
        JsonNode heartbeatA = heartbeatOk(HWID_A, tokenA, 1L, clientA);
        assertTrue(TestClientCryptoV4.verifyHeartbeat(heartbeatA, tokenA, serverSigningKey()));
        assertEquals(2L, heartbeatA.get("sequence").asLong());

        // HWID_B was flagged as the rapid-switch device, so its heartbeat delivers the poisoned
        // ResourceKey; HWID_A keeps the genuine one.
        assertArrayEquals(TestClientCrypto.poisonResourceKey(TestClientCrypto.resourceKey()),
                unwrap(clientB, heartbeatB, HWID_B),
                "heartbeat must honour the poison flag armed at activation");
        assertArrayEquals(TestClientCrypto.resourceKey(), unwrap(clientA, heartbeatA, HWID_A),
                "the poison flag must not leak to another device of the same account");
    }
}
