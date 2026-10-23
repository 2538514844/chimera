package dev.chimera.integrity;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ManifestBuilderTest {

    private final ManifestBuilder builder = new ManifestBuilder();

    @Test
    void writesHeaderAndSortedEntriesWithTwoSpaceSeparator() {
        Map<String, String> hashes = new LinkedHashMap<>();
        hashes.put("demo/Z.class", "cc");
        hashes.put("demo/A.class", "aa");
        hashes.put("demo/M.class", "bb");

        String text = new String(builder.build(hashes), StandardCharsets.UTF_8);

        assertEquals("CHM1\naa  demo/A.class\nbb  demo/M.class\ncc  demo/Z.class\n", text);
    }

    @Test
    void outputIsDeterministicRegardlessOfInsertionOrder() {
        Map<String, String> first = new LinkedHashMap<>();
        first.put("b/B.class", "22");
        first.put("a/A.class", "11");

        Map<String, String> second = new LinkedHashMap<>();
        second.put("a/A.class", "11");
        second.put("b/B.class", "22");

        assertArrayEquals(builder.build(first), builder.build(second));
    }

    @Test
    void emptyManifestContainsOnlyHeader() {
        String text = new String(builder.build(Map.of()), StandardCharsets.UTF_8);
        assertEquals("CHM1\n", text);
    }

    @Test
    void rejectsMissingHash() {
        Map<String, String> hashes = new LinkedHashMap<>();
        hashes.put("a/A.class", null);
        assertThrows(IllegalArgumentException.class, () -> builder.build(hashes));
    }

    @Test
    void fullManifestUsesChm2HeaderAndStaysSorted() {
        Map<String, String> hashes = new LinkedHashMap<>();
        hashes.put("chimera/env.dat", "bb");
        hashes.put("chimera/auth.dat", "aa");
        hashes.put("demo/A.class", "cc");

        String text = new String(builder.buildFull(hashes), StandardCharsets.UTF_8);

        assertEquals("CHM2\naa  chimera/auth.dat\nbb  chimera/env.dat\ncc  demo/A.class\n", text);
    }

    @Test
    void reservedRecordsCannotListThemselves() {
        assertTrue(ManifestBuilder.isReservedEntry("chimera/manifest.dat"));
        assertTrue(ManifestBuilder.isReservedEntry("chimera/manifest.mac"));
        assertTrue(ManifestBuilder.isReservedEntry("chimera/manifest.hmac"));
        assertFalse(ManifestBuilder.isReservedEntry("chimera/auth.dat"));
    }

    @Test
    void manifestHmacIsKeyedAndDeterministic() {
        byte[] manifest = builder.buildFull(Map.of("chimera/env.dat", "aa"));
        byte[] key = new byte[32];
        byte[] other = new byte[32];
        other[0] = 1;

        assertArrayEquals(builder.manifestHmac(manifest, key), builder.manifestHmac(manifest, key));
        assertFalse(java.util.Arrays.equals(builder.manifestHmac(manifest, key),
                builder.manifestHmac(manifest, other)));
        assertEquals(ManifestBuilder.HMAC_BYTES, builder.manifestHmac(manifest, key).length);
    }
}
