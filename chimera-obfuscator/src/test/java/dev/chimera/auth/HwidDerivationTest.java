package dev.chimera.auth;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class HwidDerivationTest {

    private static final byte[] SALT = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    @Test
    void derivationIsDeterministicAndEncodedConsistently() {
        Map<String, String> identifiers = Map.of("machine-id", "machine-1", "disk", "disk-9");
        Hwid first = HwidDerivation.derive(SALT, identifiers);
        Hwid second = HwidDerivation.derive(SALT.clone(), identifiers);
        assertArrayEquals(first.raw(), second.raw());
        assertEquals(first.hex(), second.hex());
        assertEquals(64, first.hex().length());
        assertEquals(44, first.base64().length());
        assertArrayEquals(first.raw(), Base64.getDecoder().decode(first.base64()));
        assertEquals(first.hex(), first.hex().toLowerCase());
    }

    @Test
    void identifierOrderDoesNotChangeTheHwid() {
        Map<String, String> forward = new LinkedHashMap<>();
        forward.put("a", "1");
        forward.put("b", "2");
        Map<String, String> reverse = new LinkedHashMap<>();
        reverse.put("b", "2");
        reverse.put("a", "1");
        assertArrayEquals(HwidDerivation.derive(SALT, forward).raw(),
                HwidDerivation.derive(SALT, reverse).raw());
    }

    @Test
    void saltAndIdentifierValuesChangeTheHwid() {
        Map<String, String> identifiers = Map.of("machine-id", "machine-1");
        byte[] otherSalt = SALT.clone();
        otherSalt[0] ^= 0x01;
        assertNotEquals(HwidDerivation.derive(SALT, identifiers).hex(),
                HwidDerivation.derive(otherSalt, identifiers).hex());
        assertNotEquals(HwidDerivation.derive(SALT, identifiers).hex(),
                HwidDerivation.derive(SALT, Map.of("machine-id", "machine-2")).hex());
    }

    @Test
    void lengthPrefixingAvoidsBoundaryAmbiguity() {
        Hwid left = HwidDerivation.derive(SALT, Map.of("a", "bc"));
        Hwid right = HwidDerivation.derive(SALT, Map.of("ab", "c"));
        assertNotEquals(left.hex(), right.hex());
    }

    @Test
    void rawBytesAreDefensivelyCopied() {
        Hwid hwid = HwidDerivation.derive(SALT, Map.of("machine-id", "machine-1"));
        byte[] raw = hwid.raw();
        raw[0] ^= 0x7f;
        assertFalse(Arrays.equals(raw, hwid.raw()));
        assertFalse(hwid.toString().contains(new String(hwid.raw(), StandardCharsets.UTF_8)));
    }

    @Test
    void invalidInputsAreRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> HwidDerivation.derive(new byte[15], Map.of("a", "b")));
        assertThrows(IllegalArgumentException.class,
                () -> HwidDerivation.derive(new byte[33], Map.of("a", "b")));
        assertThrows(IllegalArgumentException.class,
                () -> HwidDerivation.derive(SALT, Map.of()));
        assertThrows(NullPointerException.class,
                () -> HwidDerivation.derive(SALT, Map.of("a", (String) null)));
        assertEquals(HwidDerivation.SALT_BYTES, HwidDerivation.newInstallSalt().length);
    }
}
