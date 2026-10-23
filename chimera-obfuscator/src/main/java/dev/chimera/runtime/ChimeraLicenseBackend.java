package dev.chimera.runtime;

import java.io.File;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * G7 default activation backend: validates credentials against the baked license server and
 * installs the native session through the existing runtime path. The gate therefore blocks the
 * launch until a real activation succeeded; nothing here fakes authorization.
 */
final class ChimeraLicenseBackend implements ChimeraPreLaunch.LicenseBackend {

    private volatile ChimeraV4Session v4;

    private ChimeraV4Session v4() {
        ChimeraV4Session session = v4;
        if (session == null) {
            session = ChimeraV4Session.create(currentHwid());
            v4 = session;
        }
        return session;
    }

    private static final long HEARTBEAT_INTERVAL_MS = 60_000L;
    private static final long HEARTBEAT_RETRY_MS = 5_000L;
    private static volatile Thread heartbeatThread;

    /**
     * E: periodic session renewal.
     *
     * <p>Policy (decided 2026-10-22): <b>a failing heartbeat kills the client.</b> Rationale from
     * the product owner: if the licence server cannot be reached, the client cannot be verified, so
     * there is nothing to play with. One short retry absorbs a single dropped packet; a second
     * consecutive failure halts with exit code 4 (the same contract the gate uses).</p>
     *
     * <p>Before this existed the v4 flow renewed exactly once, at launch, so a revoked session kept
     * playing until the player restarted the game.</p>
     */
    private static void startHeartbeat(ChimeraV4Session session) {
        Thread existing = heartbeatThread;
        if (existing != null && existing.isAlive()) {
            return;
        }
        Thread thread = new Thread(() -> {
            while (true) {
                sleepUninterruptibly(HEARTBEAT_INTERVAL_MS);
                if (renew(session)) {
                    continue;
                }
                diag("heartbeat failed, retrying once");
                sleepUninterruptibly(HEARTBEAT_RETRY_MS);
                if (renew(session)) {
                    continue;
                }
                diag("heartbeat failed twice: halting (session lost)");
                Runtime.getRuntime().halt(4);
            }
        }, "chimera-heartbeat");
        thread.setDaemon(true);
        heartbeatThread = thread;
        thread.start();
        diag("heartbeat thread started");
    }

    private static boolean renew(ChimeraV4Session session) {
        long handle = session.renew();
        if (handle <= 0L) {
            return false;
        }
        try {
            ChimeraRuntime.installNativeHandle(handle);
            ChimeraRuntime.setLicenseContext(session.account(), session.licenseId(),
                    session.clientIp(), session.watermarkSignature());
            diag("heartbeat ok handle=" + handle);
            return true;
        } catch (Throwable failure) {
            diag("heartbeat handle install failed: " + failure);
            return false;
        }
    }

    /**
     * E: sleeps for the full duration no matter what.
     *
     * <p>The previous version returned on {@link InterruptedException}, so ANY code in the process
     * could stop licence renewal for good with
     * {@code Thread.getAllStackTraces().get("chimera-heartbeat").interrupt()} - a 20-line mod, no
     * licence needed, and revocation became cosmetic (red team, 2026-10-22). The loop now only ever
     * leaves by halting.</p>
     */
    private static void sleepUninterruptibly(long millis) {
        final long deadline = System.nanoTime() + millis * 1_000_000L;
        while (true) {
            final long remaining = deadline - System.nanoTime();
            if (remaining <= 0L) {
                return;
            }
            try {
                Thread.sleep(Math.max(1L, remaining / 1_000_000L));
            } catch (InterruptedException ignored) {
                // Deliberately swallowed: the interrupt flag is not re-set either, so a second
                // interrupt cannot short-circuit the next sleep.
            }
        }
    }

    private static void diag(String line) {
        try {
            java.nio.file.Path dir = java.nio.file.Path.of(
                    System.getProperty("user.home", "."), ".chimera");
            java.nio.file.Files.createDirectories(dir);
            java.nio.file.Files.writeString(dir.resolve("gate-diag.log"),
                    line + System.lineSeparator(), StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE,
                    java.nio.file.StandardOpenOption.APPEND);
        } catch (Throwable ignored) {
            // diagnostics must never break the client
        }
    }

    @Override
    public String currentHwid() {
        // G: firmware-derived id first (SMBIOS UUID + volume serial). The Java composite below is
        // only a fallback for machines where neither source is readable - it is spoofable with
        // -Duser.name, so it must never be the primary identity.
        String hardware = ChimeraRuntime.hwid();
        if (hardware != null && !hardware.isEmpty()) {
            return hardware;
        }
        try {
            String seed = InetAddress.getLocalHost().getHostName() + '|' + System.getProperty("os.name", "")
                    + '|' + System.getProperty("os.arch", "") + '|' + System.getProperty("user.name", "");
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(seed.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (Throwable ignored) {
            return "";
        }
    }

    @Override
    public boolean authorized() {
        // D: the packer's own image CRC. 1 = valid, 0 = the image was modified, -1 = this build has
        // no VMProtect SDK (dev DLL). Only a definitive 0 halts: the .text baseline taken in
        // JNI_OnLoad hashes the image it was loaded from, so it cannot see a patch that was already
        // on disk - this check can.
        int imageCrc = ChimeraRuntime.vmpImageCrc();
        diag("vmp image crc=" + imageCrc);
        // Red team: accepting -1 ("no SDK") as a pass meant patching this method to return -1 was a
        // clean fail-open. A release artifact is always built with the SDK, so -1 is tampering
        // there; dev builds keep the lenient path.
        if (imageCrc == 0 || (imageCrc == -1 && ChimeraRuntime.enforceReleasePolicy())) {
            diag("vmp image crc invalid: halting (" + imageCrc + ")");
            Runtime.getRuntime().halt(4);
        }
        ChimeraV4Session session = v4();
        if (session == null) {
            try {
                java.nio.file.Path dir = java.nio.file.Path.of(
                        System.getProperty("user.home", "."), ".chimera");
                java.nio.file.Files.createDirectories(dir);
                java.nio.file.Files.writeString(dir.resolve("gate-diag.log"),
                        "backend v4 session is null (auth.dat missing or malformed)\n",
                        java.nio.charset.StandardCharsets.UTF_8,
                        java.nio.file.StandardOpenOption.CREATE,
                        java.nio.file.StandardOpenOption.APPEND);
            } catch (Throwable ignored) {
            }
        }
        if (session != null) {
            long handle = session.authorizedHandle();
            if (handle == 0L) {
                return false;
            }
            try {
                ChimeraRuntime.installNativeHandle(handle);
                // #19: the watermark payload is built from the signed session data; the gate is the
                // only place that knows the session object.
                ChimeraRuntime.setLicenseContext(session.account(), session.licenseId(),
                        session.clientIp(), session.watermarkSignature());
                startHeartbeat(session);
                return true;
            } catch (Throwable ignored) {
                return false;
            }
        }
        // SECURITY (2026-10-22, red-team): this used to `return keyHealthy()`. keyHealthy() only
        // checks "not poisoned" + "auth.dat opens", so deleting the `pubkey=` line from auth.dat
        // made ChimeraV4Session.create() return null, the fallback report a valid licence, and the
        // gate skip the panel entirely - layers 1 and 2 of the fallback disarmed by one text edit.
        // No session means no licence: fail closed.
        return false;
    }

    @Override
    public String register(String account, char[] password, String hwid) {
        ChimeraV4Session session = v4();
        if (session == null) {
            return "auth.dat 缺少服务端配置，无法注册";
        }
        return session.register(account, password);
    }

    @Override
    public ChimeraActivationPanel.ActivationResult activate(String account, char[] password, String hwid) {
        if (account == null || account.isBlank() || password == null || password.length == 0) {
            return ChimeraActivationPanel.ActivationResult.fail(
                    ChimeraActivationPanel.Status.E_CREDENTIALS, "missing credentials");
        }
        ChimeraV4Session session = v4();
        if (session != null) {
            ChimeraV4Session.Result result = session.activate(account, password);
            if (result.activated() && result.handle() > 0L) {
                try {
                    ChimeraRuntime.installNativeHandle(result.handle());
                    ChimeraRuntime.setLicenseContext(session.account(), session.licenseId(),
                            session.clientIp(), session.watermarkSignature());
                } catch (Throwable ignored) {
                    return ChimeraActivationPanel.ActivationResult.fail(
                            ChimeraActivationPanel.Status.E_STATE, "native handle install failed");
                }
                return ChimeraActivationPanel.ActivationResult.ok(
                        result.expiresAtEpochSeconds(), result.token());
            }
            return ChimeraActivationPanel.ActivationResult.fail(result.status(), result.detail());
        }
        try {
            Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true,
                    System.getProperty("chimera.gate.loader") != null
                            ? ClassLoader.getSystemClassLoader()
                            : ChimeraLicenseBackend.class.getClassLoader());
            Method check = runtime.getMethod("preGameCheck", String.class, String.class, String.class);
            Object ok = check.invoke(null, account, new String(password), hwid);
            if (Boolean.TRUE.equals(ok) && keyHealthy()) {
                return ChimeraActivationPanel.ActivationResult.ok(0L, "");
            }
            return ChimeraActivationPanel.ActivationResult.fail(
                    ChimeraActivationPanel.Status.E_CREDENTIALS, "activation rejected");
        } catch (Throwable failure) {
            return ChimeraActivationPanel.ActivationResult.fail(
                    ChimeraActivationPanel.Status.E_NETWORK, String.valueOf(failure.getMessage()));
        }
    }

    private static boolean keyHealthy() {
        try {
            Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true,
                    ChimeraLicenseBackend.class.getClassLoader());
            Object healthy = runtime.getMethod("isKeyHealthy").invoke(null);
            return Boolean.TRUE.equals(healthy) && authConfigured();
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static boolean authConfigured() {
        try {
            Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true,
                    ChimeraLicenseBackend.class.getClassLoader());
            java.io.InputStream in = runtime.getResourceAsStream("/chimera/auth.dat");
            if (in == null) return false;
            in.close();
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }
}
