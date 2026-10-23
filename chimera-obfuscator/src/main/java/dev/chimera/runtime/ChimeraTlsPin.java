package dev.chimera.runtime;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * SPKI certificate pinning for the license handshake.
 *
 * <p>When a pin is configured, the license server's certificate is accepted only if
 * {@code SHA-256(certificate.publicKey.encoded)} equals the pinned value. This also makes
 * self-signed certificates usable: the pin is the trust anchor, so no CA is required.</p>
 *
 * <p>Injected into the protected jar next to {@link ChimeraRuntime}. Single class, no nested
 * classes, no lambdas.</p>
 */
public final class ChimeraTlsPin implements X509TrustManager {

    private static volatile byte[] pinnedSpki;

    public ChimeraTlsPin() {
    }

    /** Installs the pinned SPKI digest (SHA-256 of the SubjectPublicKeyInfo). */
    public static void setPin(byte[] spkiSha256) {
        pinnedSpki = spkiSha256 == null ? null : spkiSha256.clone();
    }

    /** True when a pin is configured. */
    public static boolean hasPin() {
        return pinnedSpki != null;
    }

    /**
     * Replaces the connection's socket factory with one whose trust manager enforces the pin.
     * Must be called before connecting.
     */
    public static void install(HttpsURLConnection connection) throws Exception {
        if (!hasPin()) {
            return;
        }
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[]{new ChimeraTlsPin()}, new SecureRandom());
        connection.setSSLSocketFactory(context.getSocketFactory());
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {
        // Client certificates are not used by the protocol.
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        byte[] pin = pinnedSpki;
        if (pin == null) {
            return;
        }
        if (chain == null || chain.length == 0) {
            throw new CertificateException("license server sent no certificate");
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] actual = digest.digest(chain[0].getPublicKey().getEncoded());
            if (!MessageDigest.isEqual(actual, pin)) {
                throw new CertificateException("license server SPKI pin mismatch");
            }
        } catch (CertificateException e) {
            throw e;
        } catch (Exception e) {
            throw new CertificateException("SPKI pin verification failed", e);
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}
