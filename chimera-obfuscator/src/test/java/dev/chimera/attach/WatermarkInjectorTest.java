package dev.chimera.attach;

import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * #19: the watermark must be (a) present in the rewritten class, (b) not break the verifier, and
 * (c) decryptable with the RSA private key that matches the baked public key.
 *
 * <p>Defining the class is the important assertion: a malformed StackMapTable or a wrong
 * {@code max_stack} fails here rather than in a player's game.</p>
 */
class WatermarkInjectorTest {

    private static final String PLAIN = "CHM-0011223344556677|client001|12345678|203.0.113.9|1700000000";

    @Test
    void injectsDecryptablePayloadWithoutBreakingVerification() throws Exception {
        byte[] original = readClass("dev/chimera/attach/AgentCipher.class");
        KeyPair keys = rsaKeyPair();
        String payload = seal(keys, PLAIN);

        byte[] marked = WatermarkInjector.inject(original, payload);

        assertTrue(marked.length > original.length, "payload constant must be added");
        assertTrue(new String(marked, StandardCharsets.ISO_8859_1).contains(payload),
                "payload must survive in the class file");
        // The JVM verifier runs on defineClass: this catches bad frames/max_stack.
        Class<?> defined = new Loader().define("dev.chimera.attach.AgentCipher", marked);
        assertNotNull(defined);
        assertEquals(PLAIN, open(keys, payload), "payload must decrypt with the private key");
    }

    @Test
    void returnsInputUnchangedWhenNoPayload() throws Exception {
        byte[] original = readClass("dev/chimera/attach/AgentCipher.class");
        assertSame(original, WatermarkInjector.inject(original, null));
        assertSame(original, WatermarkInjector.inject(original, ""));
    }

    @Test
    void returnsInputUnchangedForGarbageBytes() {
        byte[] garbage = {0x01, 0x02, 0x03, 0x04};
        assertSame(garbage, WatermarkInjector.inject(garbage, "CHMW1:AAAA"));
    }

    // ------------------------------------------------------------------ helpers

    private static byte[] readClass(String resource) throws Exception {
        try (InputStream in = WatermarkInjector.class.getResourceAsStream("/" + resource)) {
            assertNotNull(in, "class resource missing: " + resource);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) > 0) {
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        }
    }

    private static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(3072);
        return generator.generateKeyPair();
    }

    /** Same OAEP parameters as {@code ChimeraRuntime.watermarkPayload()}. */
    private static OAEPParameterSpec oaep() {
        return new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT);
    }

    private static String seal(KeyPair keys, String plain) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keys.getPublic(), oaep());
        return "CHMW1:" + Base64.getEncoder().encodeToString(
                cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8)));
    }

    private static String open(KeyPair keys, String payload) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.DECRYPT_MODE, keys.getPrivate(), oaep());
        byte[] body = Base64.getDecoder().decode(payload.substring("CHMW1:".length()));
        return new String(cipher.doFinal(body), StandardCharsets.UTF_8);
    }

    /** Defines the rewritten bytes in an isolated loader so the JVM verifier has to accept them. */
    private static final class Loader extends ClassLoader {
        Loader() {
            super(WatermarkInjectorTest.class.getClassLoader());
        }

        Class<?> define(String name, byte[] bytes) {
            return defineClass(name, bytes, 0, bytes.length);
        }
    }
}
