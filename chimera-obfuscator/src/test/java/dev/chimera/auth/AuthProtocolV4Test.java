package dev.chimera.auth;

import dev.chimera.crypto.Crypto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * S7 protocol v4 pure-logic tests: nonce/request binding, signature binding, token rotation,
 * monotonic sequence persistence, replay detection and clock skew.
 */
class AuthProtocolV4Test {

    private static final SecureRandom RANDOM = new SecureRandom();

    private MockLicenseServerV4 server;
    private InMemorySequenceStore store;
    private MutableClock clock;
    private AuthProtocolV4 protocol;

    @BeforeEach
    void setUp() throws Exception {
        server = new MockLicenseServerV4();
        store = new InMemorySequenceStore();
        clock = new MutableClock(server.now());
        protocol = new AuthProtocolV4(config(), server.publicKeyRaw());
    }

    private AuthV4Config config() {
        return AuthV4Config.builder().clock(clock).sequenceStore(store).build();
    }

    private static String clientPublicKey() {
        byte[] raw = new byte[32];
        RANDOM.nextBytes(raw);
        return Base64.getEncoder().encodeToString(raw);
    }

    private ActivationRequestV4 newActivation() throws Exception {
        return protocol.newActivation(MockLicenseServerV4.ACCOUNT, MockLicenseServerV4.HWID,
                clientPublicKey());
    }

    private AuthV4Session activate() throws Exception {
        ActivationRequestV4 request = newActivation();
        ActivationResponseV4 response = server.activate(request, clock.instant().getEpochSecond());
        return protocol.verifyActivate(request, response);
    }

    private AuthV4Session heartbeat(AuthV4Session session) throws Exception {
        HeartbeatRequestV4 request = protocol.newHeartbeat(session);
        HeartbeatResponseV4 response = server.heartbeat(request, clock.instant().getEpochSecond());
        return protocol.verifyHeartbeat(session, request, response);
    }

    private AuthProtocolException activationFailure(MockLicenseServerV4.ActivateMutation mutation,
                                                    boolean beforeSigning) throws Exception {
        server.activateMutation = mutation;
        server.mutateBeforeSigning = beforeSigning;
        ActivationRequestV4 request = newActivation();
        ActivationResponseV4 response = server.activate(request, clock.instant().getEpochSecond());
        return assertThrows(AuthProtocolException.class,
                () -> protocol.verifyActivate(request, response));
    }

    private AuthProtocolException heartbeatFailure(MockLicenseServerV4.HeartbeatMutation mutation,
                                                   boolean beforeSigning) throws Exception {
        AuthV4Session session = activate();
        server.heartbeatMutation = mutation;
        server.mutateBeforeSigning = beforeSigning;
        HeartbeatRequestV4 request = protocol.newHeartbeat(session);
        HeartbeatResponseV4 response = server.heartbeat(request, clock.instant().getEpochSecond());
        return assertThrows(AuthProtocolException.class,
                () -> protocol.verifyHeartbeat(session, request, response));
    }

    @Test
    void activationAcceptsSignedResponseAndPersistsInitialState() throws Exception {
        ActivationRequestV4 request = newActivation();
        assertNotNull(request.clientNonce());
        assertEquals(32, Base64.getDecoder().decode(request.clientNonce()).length);
        assertEquals(32, Base64.getDecoder().decode(request.clientEphemeralPub()).length);

        ActivationResponseV4 response = server.activate(request, clock.instant().getEpochSecond());
        AuthV4Session session = protocol.verifyActivate(request, response);
        assertEquals(MockLicenseServerV4.ACCOUNT, session.account());
        assertEquals(MockLicenseServerV4.HWID, session.hwid());
        assertEquals(1L, session.sequence());
        assertEquals(response.token(), session.token());
        assertEquals(response.serverNonce(), session.serverNonce());

        SequenceState state = store.state();
        assertNotNull(state);
        assertEquals(1L, state.sequence());
        assertArrayEquals(Crypto.sha256(Base64.getDecoder().decode(response.token())),
                state.tokenHash());
        assertEquals(response.issuedAt(), state.issuedAt());
        assertEquals(AuthFailure.STATE, assertThrows(AuthProtocolException.class,
                () -> protocol.loadPersistedState("other-account", MockLicenseServerV4.HWID)).failure());
    }

    @Test
    void activationRejectsBindingTamperEvenWhenSignatureIsValid() throws Exception {
        for (MockLicenseServerV4.ActivateMutation mutation : new MockLicenseServerV4.ActivateMutation[]{
                MockLicenseServerV4.ActivateMutation.ACCOUNT,
                MockLicenseServerV4.ActivateMutation.HWID,
                MockLicenseServerV4.ActivateMutation.CLIENT_EPHEMERAL_PUB,
                MockLicenseServerV4.ActivateMutation.CLIENT_NONCE}) {
            AuthProtocolException failure = activationFailure(mutation, true);
            assertEquals(AuthFailure.BINDING, failure.failure(), "mutation " + mutation);
        }
    }

    @Test
    void activationRejectsSignedFieldTamper() throws Exception {
        for (MockLicenseServerV4.ActivateMutation mutation : new MockLicenseServerV4.ActivateMutation[]{
                MockLicenseServerV4.ActivateMutation.SERVER_EPHEMERAL_PUB,
                MockLicenseServerV4.ActivateMutation.SERVER_NONCE,
                MockLicenseServerV4.ActivateMutation.TOKEN,
                MockLicenseServerV4.ActivateMutation.ISSUED_AT,
                MockLicenseServerV4.ActivateMutation.EXPIRES_AT,
                MockLicenseServerV4.ActivateMutation.SERVER_TIME,
                MockLicenseServerV4.ActivateMutation.RESOURCE_CK}) {
            AuthProtocolException failure = activationFailure(mutation, false);
            assertEquals(AuthFailure.SIGNATURE, failure.failure(), "mutation " + mutation);
        }
        AuthProtocolException sequence = activationFailure(
                MockLicenseServerV4.ActivateMutation.SEQUENCE, false);
        assertEquals(AuthFailure.SEQUENCE, sequence.failure());
    }

    @Test
    void activationRejectsTamperedSignature() throws Exception {
        server.tamperSignature = true;
        ActivationRequestV4 request = newActivation();
        ActivationResponseV4 response = server.activate(request, clock.instant().getEpochSecond());
        AuthProtocolException failure = assertThrows(AuthProtocolException.class,
                () -> protocol.verifyActivate(request, response));
        assertEquals(AuthFailure.SIGNATURE, failure.failure());
    }

    @Test
    void activationRejectsWrongVersionWrongSequenceAndStalePendingState() throws Exception {
        server.version = 3;
        ActivationRequestV4 versionRequest = newActivation();
        ActivationResponseV4 versionResponse = server.activate(versionRequest,
                clock.instant().getEpochSecond());
        assertEquals(AuthFailure.VERSION, assertThrows(AuthProtocolException.class,
                () -> protocol.verifyActivate(versionRequest, versionResponse)).failure());

        server = new MockLicenseServerV4();
        protocol = new AuthProtocolV4(config(), server.publicKeyRaw());
        server.activationSequenceNotOne = true;
        ActivationRequestV4 sequenceRequest = newActivation();
        ActivationResponseV4 sequenceResponse = server.activate(sequenceRequest,
                clock.instant().getEpochSecond());
        assertEquals(AuthFailure.SEQUENCE, assertThrows(AuthProtocolException.class,
                () -> protocol.verifyActivate(sequenceRequest, sequenceResponse)).failure());

        ActivationRequestV4 pending = newActivation();
        ActivationRequestV4 other = new ActivationRequestV4(4, pending.account(), pending.hwid(),
                pending.clientEphemeralPub(), clientPublicKey());
        ActivationResponseV4 response = server.activate(pending, clock.instant().getEpochSecond());
        assertEquals(AuthFailure.BINDING, assertThrows(AuthProtocolException.class,
                () -> protocol.verifyActivate(other, response)).failure());
        assertEquals(AuthFailure.STATE, assertThrows(AuthProtocolException.class,
                () -> protocol.verifyActivate(pending, response)).failure());
    }

    @Test
    void activationEnforcesClockSkewExpiryAndRollback() throws Exception {
        server.activationIssuedOffset = 300L;
        assertNotNull(activate(), "issued_at exactly at tolerance must be accepted");

        server = new MockLicenseServerV4();
        protocol = new AuthProtocolV4(config(), server.publicKeyRaw());
        server.activationIssuedOffset = 301L;
        ActivationRequestV4 oldRequest = newActivation();
        ActivationResponseV4 oldResponse = server.activate(oldRequest,
                clock.instant().getEpochSecond());
        assertEquals(AuthFailure.CLOCK_SKEW, assertThrows(AuthProtocolException.class,
                () -> protocol.verifyActivate(oldRequest, oldResponse)).failure());

        server = new MockLicenseServerV4();
        protocol = new AuthProtocolV4(config(), server.publicKeyRaw());
        server.activationServerTimeOffset = 301L;
        ActivationRequestV4 timeRequest = newActivation();
        ActivationResponseV4 timeResponse = server.activate(timeRequest,
                clock.instant().getEpochSecond());
        assertEquals(AuthFailure.CLOCK_SKEW, assertThrows(AuthProtocolException.class,
                () -> protocol.verifyActivate(timeRequest, timeResponse)).failure());

        server = new MockLicenseServerV4();
        protocol = new AuthProtocolV4(config(), server.publicKeyRaw());
        server.activationExpired = true;
        ActivationRequestV4 expiredRequest = newActivation();
        ActivationResponseV4 expiredResponse = server.activate(expiredRequest,
                clock.instant().getEpochSecond());
        assertEquals(AuthFailure.EXPIRED, assertThrows(AuthProtocolException.class,
                () -> protocol.verifyActivate(expiredRequest, expiredResponse)).failure());
    }

    @Test
    void heartbeatRotatesTokenAdvancesSequenceAndPersists() throws Exception {
        AuthV4Session first = activate();
        String oldToken = first.token();
        String oldNonce = first.serverNonce();

        HeartbeatRequestV4 request = protocol.newHeartbeat(first);
        HeartbeatResponseV4 response = server.heartbeat(request, clock.instant().getEpochSecond());
        AuthV4Session second = protocol.verifyHeartbeat(first, request, response);

        assertNotEquals(oldToken, second.token(), "token must rotate");
        assertEquals(2L, second.sequence());
        assertNotEquals(oldNonce, second.serverNonce(), "server nonce must rotate");
        assertTrue(second.expiresAt() > second.issuedAt());
        SequenceState state = store.state();
        assertEquals(2L, state.sequence());
        assertArrayEquals(Crypto.sha256(Base64.getDecoder().decode(second.token())),
                state.tokenHash());
    }

    @Test
    void heartbeatRejectsSignedFieldTamper() throws Exception {
        for (MockLicenseServerV4.HeartbeatMutation mutation : new MockLicenseServerV4.HeartbeatMutation[]{
                MockLicenseServerV4.HeartbeatMutation.TOKEN,
                MockLicenseServerV4.HeartbeatMutation.SERVER_NONCE,
                MockLicenseServerV4.HeartbeatMutation.ISSUED_AT,
                MockLicenseServerV4.HeartbeatMutation.EXPIRES_AT,
                MockLicenseServerV4.HeartbeatMutation.SERVER_TIME}) {
            AuthProtocolException failure = heartbeatFailure(mutation, false);
            assertEquals(AuthFailure.SIGNATURE, failure.failure(), "mutation " + mutation);
        }
        AuthProtocolException sequence = heartbeatFailure(
                MockLicenseServerV4.HeartbeatMutation.SEQUENCE, false);
        assertEquals(AuthFailure.SEQUENCE, sequence.failure());
    }

    @Test
    void heartbeatRejectsBindingTamperEvenWhenSignatureIsValid() throws Exception {
        for (MockLicenseServerV4.HeartbeatMutation mutation : new MockLicenseServerV4.HeartbeatMutation[]{
                MockLicenseServerV4.HeartbeatMutation.HWID,
                MockLicenseServerV4.HeartbeatMutation.CLIENT_NONCE}) {
            AuthProtocolException failure = heartbeatFailure(mutation, true);
            assertEquals(AuthFailure.BINDING, failure.failure(), "mutation " + mutation);
        }
        AuthProtocolException after = heartbeatFailure(
                MockLicenseServerV4.HeartbeatMutation.HWID, false);
        assertEquals(AuthFailure.BINDING, after.failure());
    }

    @Test
    void heartbeatRejectsSameTokenAndStaleSequence() throws Exception {
        server.heartbeatSameToken = true;
        AuthV4Session first = activate();
        HeartbeatRequestV4 request = protocol.newHeartbeat(first);
        HeartbeatResponseV4 response = server.heartbeat(request, clock.instant().getEpochSecond());
        assertEquals(AuthFailure.TOKEN_ROTATION, assertThrows(AuthProtocolException.class,
                () -> protocol.verifyHeartbeat(first, request, response)).failure());

        server = new MockLicenseServerV4();
        protocol = new AuthProtocolV4(config(), server.publicKeyRaw());
        server.heartbeatStaleSequence = true;
        AuthV4Session second = activate();
        HeartbeatRequestV4 staleRequest = protocol.newHeartbeat(second);
        HeartbeatResponseV4 staleResponse = server.heartbeat(staleRequest,
                clock.instant().getEpochSecond());
        assertEquals(AuthFailure.SEQUENCE, assertThrows(AuthProtocolException.class,
                () -> protocol.verifyHeartbeat(second, staleRequest, staleResponse)).failure());
    }

    @Test
    void heartbeatRejectsTamperedSignatureClockRollbackAndExpiry() throws Exception {
        AuthV4Session session = activate();
        server.tamperSignature = true;
        HeartbeatRequestV4 tamperedRequest = protocol.newHeartbeat(session);
        HeartbeatResponseV4 tamperedResponse = server.heartbeat(tamperedRequest,
                clock.instant().getEpochSecond());
        assertEquals(AuthFailure.SIGNATURE, assertThrows(AuthProtocolException.class,
                () -> protocol.verifyHeartbeat(session, tamperedRequest, tamperedResponse)).failure());

        server = new MockLicenseServerV4();
        protocol = new AuthProtocolV4(config(), server.publicKeyRaw());
        server.heartbeatOldIssuedAt = true;
        AuthV4Session rollbackSession = activate();
        HeartbeatRequestV4 rollbackRequest = protocol.newHeartbeat(rollbackSession);
        HeartbeatResponseV4 rollbackResponse = server.heartbeat(rollbackRequest,
                clock.instant().getEpochSecond());
        assertEquals(AuthFailure.CLOCK_ROLLBACK, assertThrows(AuthProtocolException.class,
                () -> protocol.verifyHeartbeat(rollbackSession, rollbackRequest,
                        rollbackResponse)).failure());

        server = new MockLicenseServerV4();
        protocol = new AuthProtocolV4(config(), server.publicKeyRaw());
        server.heartbeatExpired = true;
        AuthV4Session expiredSession = activate();
        HeartbeatRequestV4 expiredRequest = protocol.newHeartbeat(expiredSession);
        HeartbeatResponseV4 expiredResponse = server.heartbeat(expiredRequest,
                clock.instant().getEpochSecond());
        assertEquals(AuthFailure.EXPIRED, assertThrows(AuthProtocolException.class,
                () -> protocol.verifyHeartbeat(expiredSession, expiredRequest,
                        expiredResponse)).failure());
    }

    @Test
    void heartbeatRejectsReplayedResponseAndReusedNonce() throws Exception {
        AuthV4Session first = activate();
        HeartbeatRequestV4 request1 = protocol.newHeartbeat(first);
        HeartbeatResponseV4 response1 = server.heartbeat(request1,
                clock.instant().getEpochSecond());
        AuthV4Session second = protocol.verifyHeartbeat(first, request1, response1);
        long persistedSequence = store.state().sequence();

        HeartbeatRequestV4 request2 = protocol.newHeartbeat(second);
        assertEquals(AuthFailure.BINDING, assertThrows(AuthProtocolException.class,
                () -> protocol.verifyHeartbeat(second, request2, response1)).failure(),
                "old response echoes the old client_nonce");
        assertEquals(persistedSequence, store.state().sequence(), "replay must not advance state");

        server.heartbeatReuseNonce = true;
        HeartbeatRequestV4 request3 = protocol.newHeartbeat(second);
        HeartbeatResponseV4 response3 = server.heartbeat(request3,
                clock.instant().getEpochSecond());
        assertEquals(AuthFailure.NONCE_REPLAY, assertThrows(AuthProtocolException.class,
                () -> protocol.verifyHeartbeat(second, request3, response3)).failure());
    }

    @Test
    void restartUsesPersistedSequenceAndRejectsOldResponses() throws Exception {
        AuthV4Session first = activate();
        HeartbeatRequestV4 request1 = protocol.newHeartbeat(first);
        HeartbeatResponseV4 response1 = server.heartbeat(request1,
                clock.instant().getEpochSecond());
        AuthV4Session second = protocol.verifyHeartbeat(first, request1, response1);

        AuthProtocolV4 restarted = new AuthProtocolV4(config(), server.publicKeyRaw());
        HeartbeatRequestV4 replayRequest = restarted.newHeartbeat(second);
        assertThrows(AuthProtocolException.class,
                () -> restarted.verifyHeartbeat(second, replayRequest, response1));

        HeartbeatRequestV4 request2 = restarted.newHeartbeat(second);
        HeartbeatResponseV4 response2 = server.heartbeat(request2,
                clock.instant().getEpochSecond());
        AuthV4Session third = restarted.verifyHeartbeat(second, request2, response2);
        assertEquals(3L, third.sequence());
        assertEquals(3L, store.state().sequence());
    }

    @Test
    void persistedStateMismatchAndStoreFailureFailClosed() throws Exception {
        AuthV4Session session = activate();
        SequenceState valid = store.state();
        store.setState(new SequenceState(SequenceState.VERSION, valid.account(), valid.hwid(),
                valid.sequence() + 10, valid.issuedAt(), valid.tokenHash(),
                valid.serverNonceHash()));
        HeartbeatRequestV4 request = protocol.newHeartbeat(session);
        HeartbeatResponseV4 response = server.heartbeat(request, clock.instant().getEpochSecond());
        assertEquals(AuthFailure.STATE, assertThrows(AuthProtocolException.class,
                () -> protocol.verifyHeartbeat(session, request, response)).failure());

        server = new MockLicenseServerV4();
        store = new InMemorySequenceStore();
        protocol = new AuthProtocolV4(config(), server.publicKeyRaw());
        store.failOnSave = true;
        ActivationRequestV4 saveRequest = newActivation();
        ActivationResponseV4 saveResponse = server.activate(saveRequest,
                clock.instant().getEpochSecond());
        assertEquals(AuthFailure.STATE, assertThrows(AuthProtocolException.class,
                () -> protocol.verifyActivate(saveRequest, saveResponse)).failure());

        store.failOnSave = false;
        server = new MockLicenseServerV4();
        protocol = new AuthProtocolV4(config(), server.publicKeyRaw());
        AuthV4Session session2 = activate();
        store.failOnLoad = true;
        HeartbeatRequestV4 loadRequest = protocol.newHeartbeat(session2);
        HeartbeatResponseV4 loadResponse = server.heartbeat(loadRequest,
                clock.instant().getEpochSecond());
        assertEquals(AuthFailure.STATE, assertThrows(AuthProtocolException.class,
                () -> protocol.verifyHeartbeat(session2, loadRequest, loadResponse)).failure());
    }

    @Test
    void invalidInputsAndPendingStateAreRejected() throws Exception {
        assertThrows(AuthProtocolException.class,
                () -> protocol.newActivation("", MockLicenseServerV4.HWID, clientPublicKey()));
        assertThrows(AuthProtocolException.class,
                () -> protocol.newActivation(MockLicenseServerV4.ACCOUNT, "", clientPublicKey()));
        assertThrows(AuthProtocolException.class,
                () -> protocol.newActivation(MockLicenseServerV4.ACCOUNT, MockLicenseServerV4.HWID,
                        "not-base64!!"));
        assertThrows(AuthProtocolException.class,
                () -> protocol.newActivation(MockLicenseServerV4.ACCOUNT, MockLicenseServerV4.HWID,
                        Base64.getEncoder().encodeToString(new byte[31])));

        ActivationRequestV4 request = newActivation();
        ActivationResponseV4 response = server.activate(request, clock.instant().getEpochSecond());
        protocol.reset();
        assertEquals(AuthFailure.STATE, assertThrows(AuthProtocolException.class,
                () -> protocol.verifyActivate(request, response)).failure());
    }

    @Test
    void wireFieldsRoundTripForAllV4Messages() throws Exception {
        ActivationRequestV4 activationRequest = newActivation();
        assertEquals(activationRequest, ActivationRequestV4.fromFields(activationRequest.toFields()));

        ActivationResponseV4 activationResponse = server.activate(activationRequest,
                clock.instant().getEpochSecond());
        assertEquals(activationResponse,
                ActivationResponseV4.fromFields(activationResponse.toFields()));

        AuthV4Session session = protocol.verifyActivate(activationRequest, activationResponse);
        HeartbeatRequestV4 heartbeatRequest = protocol.newHeartbeat(session);
        assertEquals(heartbeatRequest, HeartbeatRequestV4.fromFields(heartbeatRequest.toFields()));

        HeartbeatResponseV4 heartbeatResponse = server.heartbeat(heartbeatRequest,
                clock.instant().getEpochSecond());
        assertEquals(heartbeatResponse,
                HeartbeatResponseV4.fromFields(heartbeatResponse.toFields()));
        assertFalse(heartbeatResponse.toFields().containsKey("password"));
    }
}