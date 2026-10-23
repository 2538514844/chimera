package dev.chimera.cli;

import dev.chimera.runtime.ChimeraV4Session;

import java.nio.file.Path;
import java.util.Base64;

/**
 * End-to-end activation helper: talks to a running license server with the v4 protocol and
 * reports the outcome (never prints key material). Used by the release acceptance script.
 */
public final class ActivationCli {

    private ActivationCli() {
    }

    public static void main(String[] args) {
        if (args.length < 5) {
            System.err.println("usage: ActivationCli <serverBaseUrl> <ed25519PubBase64>"
                    + " <account> <password> <hwid> [stateFile]");
            System.exit(2);
        }
        byte[] pinned = Base64.getDecoder().decode(args[1]);
        Path state = Path.of(args.length > 5 ? args[5]
                : System.getProperty("user.home", ".") + "/.chimera/license.dat");
        // The native verifier needs the pinned server key exactly like the game runtime does.
        dev.chimera.runtime.ChimeraRuntime.nativeSetAuthContext(pinned,
                args[2].getBytes(java.nio.charset.StandardCharsets.UTF_8));
        ChimeraV4Session session = ChimeraV4Session.create(args[0], pinned, args[4], state);
        ChimeraV4Session.Result result = session.activate(args[2], args[3].toCharArray());
        System.out.println("status=" + result.status()
                + " activated=" + result.activated()
                + " expires=" + result.expiresAtEpochSeconds()
                + " sequence=" + result.sequence()
                + " nativeHandle=" + (result.handle() > 0 ? "issued" : "missing")
                + " detail=" + (result.detail() == null ? "" : result.detail()));
        System.exit(result.activated() ? 0 : 1);
    }
}
