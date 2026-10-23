package dev.chimera.cli;

import dev.chimera.crypto.Crypto;
import dev.chimera.transform.watermark.WatermarkExtraction;
import dev.chimera.transform.watermark.WatermarkExtractor;

import java.io.DataInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.zip.ZipFile;

/** Extracts the build/license watermark from a protected jar. */
public final class WatermarkMain {

    private WatermarkMain() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("usage: WatermarkMain <jar> <passphrase|64-hex-key>");
            System.exit(2);
        }
        Path jar = Path.of(args[0]);
        byte[] material = deriveMaterial(args[1]);
        byte[] kek = Crypto.hkdf(material,
                "chimera-kek-v1".getBytes(StandardCharsets.UTF_8),
                "kek".getBytes(StandardCharsets.UTF_8), 32);
        byte[] salt;
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            var entry = zip.getEntry("chimera/env.dat");
            if (entry == null) {
                System.err.println("not a chimera artifact: chimera/env.dat missing");
                System.exit(3);
            }
            try (InputStream raw = zip.getInputStream(entry);
                 DataInputStream in = new DataInputStream(raw)) {
                if (in.readInt() != 0x43485631) {
                    System.err.println("bad environment magic");
                    System.exit(3);
                }
                int version = in.readInt();
                if (version >= 2) in.readInt();
                salt = new byte[in.readInt()];
                in.readFully(salt);
            }
        }
        WatermarkExtraction extraction = WatermarkExtractor.usingKek(kek, salt).extract(jar);
        System.out.println("recovered=" + extraction.recovered()
                + " confidence=" + extraction.confidence()
                + " layers=" + extraction.hitLayers());
        System.out.println("buildId=" + extraction.buildId());
        System.out.println("licenseTag=" + extraction.licenseTagHex());
        System.out.println("shards valid=" + extraction.shardsValid()
                + " variants=" + extraction.variantClassesRecovered()
                + " structure=" + extraction.structureClassesRecovered());
        if (!extraction.recovered()) {
            System.out.println("reason=" + extraction.failureReason());
            System.exit(1);
        }
    }

    private static byte[] deriveMaterial(String value) {
        if (value.matches("[0-9a-fA-F]{16,128}") && value.length() % 2 == 0) {
            return Crypto.unhex(value);
        }
        return Crypto.sha256(value.getBytes(StandardCharsets.UTF_8));
    }
}
