package dev.chimera.runtime;

/**
 * G7: pre-launch gate. Runs from {@code fabric.mod.json} {@code preLaunch} before Minecraft and
 * before any other mod initialises; without a valid license it must not let the game load at all.
 *
 * <p>The gate itself holds no bypass: a release build without an authorized license shows the
 * activation panel and terminates the JVM when it is dismissed. The v4 client wiring installs a
 * {@link LicenseBackend}; a dev build (env.dat flags, see {@code DebugSwitches}) may skip the
 * panel because its resource key is checked by the runtime anyway.</p>
 */
public final class ChimeraPreLaunch {

    /** Guards {@link #onPreLaunch()} so the mixin-delegate call and the entrypoint call run once. */
    private static final java.util.concurrent.atomic.AtomicBoolean STARTED =
            new java.util.concurrent.atomic.AtomicBoolean();

    /** Implemented by the license wiring (v4 auth + native handle). */
    public interface LicenseBackend {
        /** Stable machine id shown in the panel (derived from HWID derivation rules). */
        String currentHwid();

        /** True when persisted authorization state is present, current and matches this HWID. */
        boolean authorized();

        /** Performs the activation round-trip; must never throw for normal failures. */
        ChimeraActivationPanel.ActivationResult activate(String account, char[] password, String hwid);

        /**
         * Self-service registration against a pre-registered HWID (onboarding, 2026-10-22).
         *
         * @return {@code null} on success, otherwise a player-facing message
         */
        default String register(String account, char[] password, String hwid) {
            return "this build does not support self-registration";
        }
    }

    // SECURITY (audit 2026-10-22 #3): both fields are private. A third-party mod can declare
    // dev.chimera.runtime and reach package-private members of this class in Fabric's flat
    // classloader, so a package-private `gateAuthorized`/`backend` field would be a one-line
    // bypass regardless of how the *ForTests methods are gated.
    private static volatile LicenseBackend backend;

    /**
     * P0-1: true once this JVM established a <b>positively authorized</b> licence at the gate. The
     * dev-bypass path never sets it, so a patched flag/resource leaves it false and the post-gate
     * stages refuse to start a release artifact. Not a user-facing switch: no property or system
     * call can set it from outside this class.
     */
    private static volatile boolean gateAuthorized;

    private ChimeraPreLaunch() {
    }

    /**
     * Installed by the runtime/license wiring before {@link #onPreLaunch()} can run.
     *
     * <p><b>Package-private on purpose.</b> A blind red-team run (2026-10-23) pointed straight at
     * this method: it is the single switch that makes {@code authorized()} true, and while it was
     * {@code public} any injected class - a bundled sub-mod, for example - could install a backend
     * that always returns "authorized" and skip the whole gate. The runtime classes are renamed to
     * opaque single-letter packages in the product jar, so an attacker can no longer even name the
     * package this call has to live in.</p>
     */
    static void installBackend(LicenseBackend licenseBackend) {
        backend = licenseBackend;
    }

    /**
     * Fabric {@code preLaunch} entrypoint. Blocks (activation panel) or terminates when the
     * license is not valid, so the game never reaches its loading screen unlicensed.
     */
    /** S5: defines NUL-named classes into the Fabric loader before any of them is resolved. */
    private static void registerHiddenClasses() {
        try {
            ChimeraHiddenRegistry.Result result =
                    ChimeraHiddenRegistry.install(ChimeraPreLaunch.class.getClassLoader());
            if (result.hiddenEntries() > 0 && !result.ok()) {
                terminate();
            }
        } catch (Throwable ignored) {
            // No runtime class / no hidden entries: names remain resolvable normally.
        }
    }

    private static void diag(String line) {
        try {
            java.nio.file.Path dir = java.nio.file.Path.of(
                    System.getProperty("user.home", "."), ".chimera");
            java.nio.file.Files.createDirectories(dir);
            java.nio.file.Files.writeString(dir.resolve("gate-diag.log"),
                    line + System.lineSeparator(), java.nio.charset.StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE,
                    java.nio.file.StandardOpenOption.APPEND);
        } catch (Throwable ignored) {
        }
    }

    private static void installHiddenClasses() {
        try {
            ClassLoader loader = ChimeraPreLaunch.class.getClassLoader();
            // Direct reference (not a class-name string) so --rename-runtime remapping still works.
            Object result = ChimeraHiddenRegistry.install(loader);
            diag("prelaunch hidden " + result);
        } catch (Throwable failure) {
            diag("prelaunch hidden failed " + failure);
        }
    }

    public static void onPreLaunch() {
        // Idempotent: the gate is now invoked from ChimeraMixinDelegate.boot() (before the agent
        // attaches) and again from the preLaunch entrypoint. Only the first call may run it.
        if (!STARTED.compareAndSet(false, true)) {
            return;
        }
        // #24 payload-stealth: when the artifact carries the disguised blob instead of a plain
        // /chimera/embedded.dll, materialise it through the Hachimi-shaped staging loader.
        // Class.getResource() resolves relative names against this class's package, so the
        // resource path must be absolute here (ClassLoader.getResource in ChimeraEngineGate is not).
        ChimeraPayload.ensureLoaded();
        // VM mode: the artifact runs as an inert mod (every class body is stubbed), so skip the
        // gate entirely - no panel, no heartbeat. Must come AFTER the payload load: asking the
        // native module would otherwise initialise ChimeraRuntime too early and it would miss the
        // staged DLL (that ordering bug already cost us a halt(4) once).
        if (ChimeraMixinDelegate.vmEmptyMode()) {
            diag("vm inert mode: gate skipped");
            return;
        }
        // #9: the DLL is loaded, so the manifest can now be authenticated with its pinned key.
        // This must happen before any chimera/** resource is consumed (env.dat here, auth.dat in
        // the gate): a tampered auth.dat/env.dat/strings.dat/native.dat halts with exit code 4.
        try {
            ChimeraRuntime.verifyResourceManifest();
        } catch (Throwable ignored) {
            // no runtime class in this artifact: nothing claims chimera/** coverage
        }
        // P0-1: the release DLL is the build-kind anchor; apply it before any policy decision.
        try {
            ChimeraRuntime.refreshBuildPolicy();
        } catch (Throwable ignored) {
            // no runtime class in this artifact: the gate stays fail-closed below
        }
        try {
            Class.forName("dev.chimera.transform.indy.ChimeraBootstrap", true,
                    ChimeraPreLaunch.class.getClassLoader())
                    .getMethod("markGatePassed").invoke(null);
        } catch (Throwable ignored) {
            // Without the indy runtime the flag is irrelevant.
        }
        diag("preLaunch enter backend=" + backend);
        // Class initialisation installs the default backend (see ChimeraRuntime static block).
        try {
            Class.forName("dev.chimera.runtime.ChimeraRuntime", true,
                    ChimeraPreLaunch.class.getClassLoader());
        } catch (Throwable ignored) {
            // Without the runtime the gate stays fail-closed (panel + halt).
        }
        LicenseBackend active = backend;
        boolean devBypass = developerBypassAllowed();
        boolean authorized = false;
        if (!devBypass && active != null) {
            try {
                authorized = active.authorized();
            } catch (Throwable ignored) {
                authorized = false;
            }
        }
        diag("gate devBypass=" + devBypass + " authorized=" + authorized);
        if (!shouldBlock(devBypass, authorized)) {
            gateAuthorized = authorized;
            // Early hidden tier: classes referenced by Mixin bytecode must exist before mixin
        // application; the remaining hidden classes are defined after Bootstrap.
        try {
            ChimeraHiddenRegistry.defineEarly(ChimeraPreLaunch.class.getClassLoader());
        } catch (Throwable ignored) {
            // fail closed later when a hidden class is actually requested
        }
        // native sink registration and the remaining hidden classes run from the main entrypoint
            diag("gate leave (authorized)");
            return;
        }
        String hwid = "";
        if (active != null) {
            try {
                hwid = active.currentHwid();
            } catch (Throwable ignored) {
                hwid = "";
            }
        }
        final LicenseBackend target = active;
        ChimeraActivationPanel panel = new ChimeraActivationPanel(
                target == null ? null : new PanelActivator(target), hwid);
        diag("gate blocking: showing panel");
        ChimeraActivationPanel.ActivationResult result = panel.showBlocking();
        if (!result.activated()) {
            terminate();
        }
        gateAuthorized = true;
        diag("gate authorized via activation panel");
    }

    /** Pure decision used by tests: no bypass and no authorization means block. */
    static boolean shouldBlock(boolean devBypass, boolean authorized) {
        return !devBypass && !authorized;
    }

    /**
     * Adapter that lets the activation panel call either {@code activate} or {@code register}.
     *
     * <p><b>Named, not anonymous, on purpose.</b> {@code ChimeraEngine.RUNTIME_CLASSES} is a
     * hand-written whitelist of runtime classes that get injected into the product jar; an anonymous
     * class compiles to {@code ChimeraPreLaunch$1}, a name nobody remembers to register and one that
     * silently renumbers whenever the enclosing source changes. That exact bug shipped on
     * 2026-10-22: the class was absent from the artifact, so <i>every unlicensed launch</i> died at
     * preLaunch with {@code NoClassDefFoundError: dev/chimera/runtime/ChimeraPreLaunch$1} before the
     * activation panel could ever be shown - i.e. no new customer could be onboarded. It went
     * unnoticed because every test after the register feature landed was run on an already-activated
     * machine, where this branch is never taken.</p>
     */
    private static final class PanelActivator implements ChimeraActivationPanel.Activator {

        private final LicenseBackend target;

        PanelActivator(LicenseBackend target) {
            this.target = target;
        }

        @Override
        public ChimeraActivationPanel.ActivationResult activate(String account, char[] password,
                                                                String hwidValue) {
            return target.activate(account, password, hwidValue);
        }

        @Override
        public String register(String account, char[] password, String hwidValue) {
            return target.register(account, password, hwidValue);
        }
    }

    /**
     * P0-1 "bypass means death", stage 2: called by the post-gate entrypoints (mixin plugin
     * bootstrap, generated main) after the game started loading.
     *
     * <p>A release artifact that never recorded an authorized licence is refused here, no matter
     * how the gate was talked out of blocking (patched decision, deleted release resources, flipped
     * {@code env.dat} flag). The check is deliberately independent of the gate's own flags: it does
     * not read them, it only reads the authorization record this class set itself.</p>
     */
    public static void requireGateAuthorized(String stage) {
        if (gateAuthorized) return;
        boolean enforced;
        try {
            enforced = ChimeraRuntime.enforceReleasePolicy();
        } catch (Throwable ignored) {
            enforced = true; // fail closed: a runtime that cannot answer is a release artifact
        }
        if (!postGateMustHalt(gateAuthorized, enforced)) {
            diag("post-gate check skipped (dev artifact) stage=" + stage);
            return;
        }
        diag("post-gate unauthorized halt stage=" + stage);
        System.err.println("[chimera] licence gate was not satisfied for this start; refusing to run");
        Runtime.getRuntime().halt(4);
    }

    /** Pure decision used by tests: an enforced artifact with no authorized gate must halt. */
    static boolean postGateMustHalt(boolean authorized, boolean enforced) {
        return enforced && !authorized;
    }

    /**
     * Tests only: forget the recorded authorization so the halt decision can be exercised.
     *
     * <p>SECURITY (audit 2026-10-22 #3): a no-op in every artifact that ships a native payload and
     * whenever a release DLL is loaded, so a mod that declares {@code dev.chimera.runtime} cannot
     * reset the flag either.</p>
     */
    static void resetForTests() {
        if (!ChimeraRuntime.testSeamsAllowed()) {
            return;
        }
        gateAuthorized = false;
    }

    /** Tests only: mark the gate as authorized (mirrors a licensed start). */
    static void markAuthorizedForTests() {
        if (!ChimeraRuntime.testSeamsAllowed()) {
            return;
        }
        gateAuthorized = true;
    }

    /**
     * Dev/test builds may skip the panel only when the runtime is not a release artifact. A jar
     * without env.dat is not a protected artifact, so it keeps dev semantics (same rule as
     * {@code DebugSwitches}).
     */
    static boolean developerBypassAllowed() {
        // SECURITY (audit 2026-10-22): the dev flag lives in chimera/env.dat as plain flags at
        // offset 8..11, so a 4-byte patch flipped a release artifact into "dev" mode and skipped the
        // licence gate entirely (reproduced: gate devBypass=true authorized=false -> game launched).
        // A release artifact is identified by resources only a release build carries (signed string
        // table + native auth config); if any of them exists, the dev bypass is refused no matter
        // what env.dat claims. Dev artifacts don't have them, so dev iteration still works.
        try {
            // P0-1: the native release DLL is the anchor, so deleting strings.mac/auth.dat no
            // longer turns a shipped artifact into a "dev" one.
            if (ChimeraRuntime.enforceReleasePolicy()) {
                diag("devBypass refused: release artifact");
                return false;
            }
        } catch (Throwable ignored) {
            // fall through to the flag check
        }
        try {
            // Resolve env.dat first: DebugSwitches reports UNKNOWN (dev semantics) until the
            // environment is loaded, and a release artifact must never pass the gate on that.
            Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true,
                    ChimeraPreLaunch.class.getClassLoader());
            runtime.getMethod("prepareForGate").invoke(null);
            return DebugSwitches.state() == DebugSwitches.DEV;
        } catch (Throwable ignored) {
            return false;
        }
    }

    /**
     * Hard stop: halt without running shutdown hooks so no game code can swallow the failure.
     *
     * <p>Exit code 4 is the documented fail-closed contract (C2 #30): the launcher, the license
     * panel and support scripts all distinguish "refused to start" from a normal crash (1).</p>
     */
    static void terminate() {
        diag("gate terminate halt(4)");
        Runtime.getRuntime().halt(4);
    }
}
