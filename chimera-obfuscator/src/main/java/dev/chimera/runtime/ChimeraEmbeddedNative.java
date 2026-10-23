package dev.chimera.runtime;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Single-jar bootstrap: materialises the embedded native DLL ({@code /chimera/embedded.dll}) to a
 * temporary file and loads it before the preLaunch gate. Fail-closed: any I/O or load failure
 * aborts startup instead of continuing without native protection.
 */
final class ChimeraEmbeddedNative {

    private static volatile boolean attempted;

    private ChimeraEmbeddedNative() {
    }

    static void ensureLoaded() {
        if (attempted) {
            return;
        }
        synchronized (ChimeraEmbeddedNative.class) {
            if (attempted) {
                return;
            }
            attempted = true;
            // SECURITY (audit 2026-10-22 #5): an artifact that ships a native payload declares so
            // at build time. For it the payload is mandatory: no property shortcut, and a missing
            // resource halts(4) instead of silently degrading to dev semantics.
            boolean required = ChimeraBuildFlags.payloadRequired();
            String configured = System.getProperty("chimera.native.auth.path", "");
            if (!required && !configured.isEmpty() && Files.isRegularFile(Path.of(configured))) {
                return;
            }
            String resourceName = "chimera/embedded.dll";
            InputStream raw = ChimeraEmbeddedNative.class.getResourceAsStream("/" + resourceName);
            if (raw == null) {
                if (required) {
                    missingPayload(resourceName);
                }
                return;  // split delivery: jar without embedded DLL stays supported for dev builds
            }
            // #9: hash the image against the build manifest while it is copied out, before
            // System.load sees it (same pre-load rule as the stealth path).
            String expected = ChimeraStealthLoader.expectedManifestHash(resourceName);
            try (java.security.DigestInputStream in = new java.security.DigestInputStream(
                    raw, java.security.MessageDigest.getInstance("SHA-256"))) {
                Path temp = Files.createTempFile("chm", ".tmp");
                temp.toFile().deleteOnExit();
                try (java.io.OutputStream out = Files.newOutputStream(temp)) {
                    in.transferTo(out);
                }
                if (expected != null && !expected.equalsIgnoreCase(
                        ChimeraStealthLoader.toHex(in.getMessageDigest().digest()))) {
                    throw new IllegalStateException(
                            "embedded native does not match the build manifest");
                }
                System.load(temp.toAbsolutePath().toString());
                System.setProperty("chimera.native.auth.path", temp.toAbsolutePath().toString());
            } catch (Throwable failure) {
                throw new IllegalStateException("embedded native load failed", failure);
            }
        }
    }

    /**
     * #5: the build embedded a native payload and it is gone. Continuing would let the runtime
     * fall back to the editable {@code env.dat} build kind, i.e. dev semantics with every
     * diagnostic override live, so this is tampering: halt(4) before any gate decision.
     */
    private static void missingPayload(String resourceName) {
        System.err.println("[chimera] native payload missing (" + resourceName
                + "); refusing to start without the native protection layer");
        Runtime.getRuntime().halt(4);
    }
}
