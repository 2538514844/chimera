package dev.chimera.license.tools;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * #19 forensic tool: turns {@code CHMW1:} watermark constants back into
 * {@code licenseId|account|qq|ip|ts}.
 *
 * <p>Usage:</p>
 * <pre>
 *   java -cp chimera-license-server-0.1.0.jar dev.chimera.license.tools.WatermarkExtract \
 *        [--keys data/keys] &lt;jar|class|payload&gt; ...
 * </pre>
 *
 * <p>File arguments are scanned for the literal prefix, so pointing it at a leaked jar is enough:
 * every watermarked class body carries the same constant, and duplicates are collapsed. Runs
 * offline against {@code data/keys/wm-rsa.pk8} - no server, no database.</p>
 */
public final class WatermarkExtract {

    private static final String PREFIX = "CHMW1:";

    private WatermarkExtract() {
    }

    public static void main(String[] args) throws Exception {
        Path keyDir = Path.of("data/keys");
        Set<String> inputs = new LinkedHashSet<>();
        for (int i = 0; i < args.length; i++) {
            if ("--keys".equals(args[i]) && i + 1 < args.length) {
                keyDir = Path.of(args[++i]);
            } else {
                inputs.add(args[i]);
            }
        }
        Path privatePath = keyDir.resolve("wm-rsa.pk8");
        if (!Files.isRegularFile(privatePath)) {
            System.err.println("watermark private key not found: " + privatePath);
            System.exit(2);
        }
        PrivateKey privateKey = java.security.KeyFactory.getInstance("RSA")
                .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(
                        Files.readAllBytes(privatePath)));
        PublicKey serverKey = loadServerPublicKey(keyDir);

        int found = 0;
        for (String input : inputs) {
            Path path = Path.of(input);
            Set<String> payloads = Files.isRegularFile(path)
                    ? scan(Files.readAllBytes(path)) : Set.of(input);
            for (String payload : payloads) {
                String plain = decrypt(privateKey, payload);
                System.out.println(payload.length() + " chars -> " + plain
                        + "  [" + verify(serverKey, plain) + "]");
                found++;
            }
        }
        if (found == 0) {
            System.err.println("no " + PREFIX + " payload found in: " + inputs);
            System.exit(1);
        }
    }

    /** Extracts every distinct Base64 payload that follows the literal prefix. */
    private static Set<String> scan(byte[] bytes) {
        String text = new String(bytes, StandardCharsets.ISO_8859_1);
        Set<String> out = new LinkedHashSet<>();
        int from = 0;
        while (true) {
            int start = text.indexOf(PREFIX, from);
            if (start < 0) {
                return out;
            }
            int end = start + PREFIX.length();
            while (end < text.length() && isBase64(text.charAt(end))) {
                end++;
            }
            if (end > start + PREFIX.length()) {
                out.add(text.substring(start, end));
            }
            from = end;
        }
    }

    private static boolean isBase64(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                || c == '+' || c == '/' || c == '=';
    }

    /**
     * Verifies the trailing signature against the server's Ed25519 public key.
     *
     * <p>The payload format is {@code licenseId|account|qq|ip|ts|wmSig}. The signature covers
     * {@code "chimera-wm-v1|licenseId|account"} and is issued by the licence server at activation,
     * so a payload that names somebody else's licence cannot carry a valid one. Payloads without a
     * signature (builds before #19b) are reported as unverified rather than rejected - they are
     * still useful evidence, just weaker.</p>
     */
    private static String verify(PublicKey serverKey, String plain) {
        if (serverKey == null) {
            return "UNVERIFIED (no ed25519.pub)";
        }
        String[] parts = plain.split("\\|", -1);
        if (parts.length < 6 || parts[5].isEmpty()) {
            return "UNVERIFIED (no signature)";
        }
        try {
            byte[] message = ("chimera-wm-v1|" + parts[0] + "|" + parts[1])
                    .getBytes(StandardCharsets.UTF_8);
            java.security.Signature verifier = java.security.Signature.getInstance("Ed25519");
            verifier.initVerify(serverKey);
            verifier.update(message);
            boolean ok = verifier.verify(Base64.getDecoder().decode(parts[5]));
            return ok ? "VERIFIED" : "SIGNATURE MISMATCH";
        } catch (Exception failure) {
            return "UNVERIFIED (" + failure.getClass().getSimpleName() + ")";
        }
    }


    /** The server's Ed25519 signing key (same one that signs v4 responses). */
    private static PublicKey loadServerPublicKey(Path keyDir) {
        Path publicPath = keyDir.resolve("ed25519.pub");
        if (!Files.isRegularFile(publicPath)) {
            return null;
        }
        try {
            return java.security.KeyFactory.getInstance("Ed25519")
                    .generatePublic(new java.security.spec.X509EncodedKeySpec(
                            Files.readAllBytes(publicPath)));
        } catch (Exception failure) {
            return null;
        }
    }

    private static String decrypt(PrivateKey key, String payload) {
        try {
            String body = payload.startsWith(PREFIX) ? payload.substring(PREFIX.length()) : payload;
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            // Must match ChimeraRuntime.watermarkPayload(): SHA-256 for both the digest and MGF1.
            cipher.init(Cipher.DECRYPT_MODE, key, new OAEPParameterSpec("SHA-256", "MGF1",
                    MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
            byte[] plain = cipher.doFinal(Base64.getDecoder().decode(body));
            return new String(plain, StandardCharsets.UTF_8);
        } catch (Exception failure) {
            return "<undecryptable: " + failure.getClass().getSimpleName() + ">";
        }
    }
}
