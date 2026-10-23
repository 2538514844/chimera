package dev.chimera.license.crypto;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthTranscriptV4Test {

    @Test
    void encodesDomainAndFieldsAsU32BeLengthPrefixedUtf8() {
        byte[] encoded = AuthTranscriptV4.encode("d", "a", "1");
        assertEquals("000000016400000001610000000131", hex(encoded),
                "golden vector shared with the client AuthTranscriptV4Test");
    }

    @Test
    void lengthPrefixCountsUtf8BytesNotCharacters() {
        byte[] encoded = AuthTranscriptV4.encode("d", "é");
        assertEquals(2, readInt(encoded, 5), "é is two UTF-8 bytes");
        assertEquals(encoded.length, 4 + 1 + 4 + 2);
    }

    @Test
    void activateResponseUsesExactClientFieldOrder() {
        byte[] canonical = AuthTranscriptV4.activateResponse(4, "acct", "hwid", "client-epk",
                "client-nonce", "server-epk", "server-nonce", "token", 1L, 100L, 200L, 100L,
                "resource-ck", "CHM-0011223344556677", "203.0.113.9");
        assertEquals(List.of(
                        "chimera-auth-v4/activate-response",
                        "4", "acct", "hwid", "client-epk", "client-nonce", "server-epk",
                        "server-nonce", "token", "1", "100", "200", "100", "resource-ck",
                        "CHM-0011223344556677", "203.0.113.9"),
                decode(canonical));
    }

    @Test
    void nullResourceCkIsEncodedAsEmptyString() {
        byte[] canonical = AuthTranscriptV4.activateResponse(4, "acct", "hwid", "client-epk",
                "client-nonce", "server-epk", "server-nonce", "token", 1L, 100L, 200L, 100L,
                null, null, null);
        List<String> fields = decode(canonical);
        assertEquals(16, fields.size(), "domain + 15 canonical fields (#17 added license_id/client_ip)");
        assertEquals("", fields.get(fields.size() - 1));
        assertEquals("", fields.get(fields.size() - 2));
    }

    @Test
    void heartbeatResponseBindsPresentedTokenHashAndRotatedToken() {
        byte[] canonical = AuthTranscriptV4.heartbeatResponse(4, "hwid", "client-nonce",
                "presented-token", "new-token", 2L, "server-nonce", 100L, 200L, 100L,
                "resource-ck", "server-pub", "CHM-0011223344556677", "203.0.113.9");
        List<String> fields = decode(canonical);
        assertEquals(List.of(
                        "chimera-auth-v4/heartbeat-response",
                        "4", "hwid", "client-nonce", AuthTranscriptV4.tokenHashHex("presented-token"),
                        "new-token", "2", "server-nonce", "100", "200", "100",
                        "resource-ck", "server-pub", "CHM-0011223344556677", "203.0.113.9"),
                fields);
        assertTrue(fields.get(4).matches("[0-9a-f]{64}"));
    }

    @Test
    void tokenHashIsLowercaseSha256HexAndRawTokenIsNotPresent() {
        String token = "dG9rZW4=";
        String hash = AuthTranscriptV4.tokenHashHex(token);
        assertEquals(64, hash.length());
        assertTrue(hash.matches("[0-9a-f]{64}"));
        assertNotEquals(token, hash);
    }

    @Test
    void responseDomainsAreDistinct() {
        assertNotEquals(AuthTranscriptV4.ACTIVATE_RESPONSE_DOMAIN,
                AuthTranscriptV4.HEARTBEAT_RESPONSE_DOMAIN);
    }

    private static List<String> decode(byte[] encoded) {
        List<String> fields = new ArrayList<>();
        int offset = 0;
        while (offset < encoded.length) {
            int length = readInt(encoded, offset);
            offset += 4;
            fields.add(new String(encoded, offset, length, StandardCharsets.UTF_8));
            offset += length;
        }
        assertEquals(encoded.length, offset, "no trailing bytes");
        return fields;
    }

    private static int readInt(byte[] data, int offset) {
        return ((data[offset] & 0xff) << 24)
                | ((data[offset + 1] & 0xff) << 16)
                | ((data[offset + 2] & 0xff) << 8)
                | (data[offset + 3] & 0xff);
    }

    private static String hex(byte[] value) {
        StringBuilder out = new StringBuilder(value.length * 2);
        for (byte b : value) {
            out.append(Character.forDigit((b >> 4) & 0xf, 16));
            out.append(Character.forDigit(b & 0xf, 16));
        }
        return out.toString();
    }
}
