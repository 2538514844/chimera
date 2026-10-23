package dev.chimera.auth;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthTranscriptV4Test {

    private static ActivationResponseV4 activation(String account, String hwid, String clientNonce,
                                                   String resourceCk) {
        return new ActivationResponseV4(4, account, hwid, "Y2xpZW50LWVway1iNjQ=", clientNonce,
                "c2VydmVyLWVway1iNjQ=", "c2VydmVyLW5vbmNl", "dG9rZW4=", 1L, 1_760_000_000L,
                1_760_003_600L, 1_760_000_000L, resourceCk, "c2ln");
    }

    private static HeartbeatResponseV4 heartbeat(String hwid, String nonce, String token) {
        return new HeartbeatResponseV4(4, hwid, nonce, token, 2L, "bmV3LW5vbmNl",
                1_760_000_001L, 1_760_003_601L, 1_760_000_001L, "c2ln");
    }

    @Test
    void encodeUsesLengthPrefixedDomainAndFields() {
        byte[] encoded = AuthTranscriptV4.encode("d", "a", "1");
        assertEquals("000000016400000001610000000131", hex(encoded));
    }

    @Test
    void activationCanonicalBindsEveryRequestAndResponseField() {
        ActivationResponseV4 base = activation("account", "hwid", "Y2xpZW50LW5vbmNl", "cmVzb3VyY2U=");
        byte[] canonical = AuthTranscriptV4.activateResponse(base);
        assertTrue(new String(canonical, StandardCharsets.ISO_8859_1)
                .contains("chimera-auth-v4/activate-response"));
        assertTrue(canonical.length > 200);

        assertNotEquals(hex(canonical), hex(AuthTranscriptV4.activateResponse(
                activation("other-account", "hwid", "Y2xpZW50LW5vbmNl", "cmVzb3VyY2U="))));
        assertNotEquals(hex(canonical), hex(AuthTranscriptV4.activateResponse(
                activation("account", "other-hwid", "Y2xpZW50LW5vbmNl", "cmVzb3VyY2U="))));
        assertNotEquals(hex(canonical), hex(AuthTranscriptV4.activateResponse(
                activation("account", "hwid", "b3RoZXItbm9uY2U=", "cmVzb3VyY2U="))));
        assertNotEquals(hex(canonical), hex(AuthTranscriptV4.activateResponse(
                activation("account", "hwid", "Y2xpZW50LW5vbmNl", "b3RoZXItcmVzb3VyY2U="))));
        assertNotEquals(hex(canonical), hex(AuthTranscriptV4.activateResponse(
                new ActivationResponseV4(4, "account", "hwid", "b3RoZXItZXBr", "Y2xpZW50LW5vbmNl",
                        "c2VydmVyLWVway1iNjQ=", "c2VydmVyLW5vbmNl", "dG9rZW4=", 1L,
                        1_760_000_000L, 1_760_003_600L, 1_760_000_000L, "cmVzb3VyY2U=", "c2ln"))));
    }

    @Test
    void heartbeatCanonicalBindsPresentedTokenHashAndRotatedToken() {
        String presented = "b2xkLXRva2Vu";
        HeartbeatResponseV4 response = heartbeat("hwid", "bm9uY2U=", "bmV3LXRva2Vu");
        byte[] canonical = AuthTranscriptV4.heartbeatResponse(response, presented);
        String canonicalText = new String(canonical, StandardCharsets.ISO_8859_1);
        assertTrue(canonicalText.contains(AuthTranscriptV4.tokenHashHex(presented)));
        assertTrue(canonicalText.contains("chimera-auth-v4/heartbeat-response"));

        assertNotEquals(hex(canonical), hex(AuthTranscriptV4.heartbeatResponse(response, "b3RoZXItdG9rZW4=")));
        assertNotEquals(hex(canonical),
                hex(AuthTranscriptV4.heartbeatResponse(heartbeat("hwid", "bm9uY2U=", "b3RoZXItbmV3"), presented)));
    }

    @Test
    void transcriptDomainsAndVersionsAreSeparated() {
        assertNotEquals(AuthTranscriptV4.ACTIVATE_RESPONSE_DOMAIN,
                AuthTranscriptV4.HEARTBEAT_RESPONSE_DOMAIN);
        byte[] activate = AuthTranscriptV4.activateRequest(new ActivationRequestV4(4, "a", "h", "cA==", "bg=="));
        byte[] heartbeat = AuthTranscriptV4.heartbeatRequest(new HeartbeatRequestV4(4, "h", "dA==", "bg==", 1L));
        assertFalse(Arrays.equals(activate, heartbeat));
        assertEquals(64, AuthTranscriptV4.tokenHashHex("dG9rZW4=").length());
        assertTrue(AuthTranscriptV4.tokenHashHex("dG9rZW4=").matches("[0-9a-f]{64}"));
    }

    private static String hex(byte[] value) {
        StringBuilder sb = new StringBuilder(value.length * 2);
        for (byte b : value) {
            sb.append(Character.forDigit((b >> 4) & 0xf, 16));
            sb.append(Character.forDigit(b & 0xf, 16));
        }
        return sb.toString();
    }
}
