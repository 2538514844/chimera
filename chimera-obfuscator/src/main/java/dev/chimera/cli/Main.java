package dev.chimera.cli;

import dev.chimera.core.ChimeraConfig;
import dev.chimera.core.ChimeraEngine;
import dev.chimera.core.Stats;
import dev.chimera.crypto.Crypto;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Command line entry point: java -jar chimera-all.jar --input a.jar --output b.jar --key-pass secret */
public final class Main {
    public static void main(String[] args) {
        // G1.10: a self-protected engine (embedded payload) refuses to run without a license.
        // P1-1: this must happen *before* the attach agent, because the agent derives its class key
        // from the native SessionHandle the gate installs; attaching first would leave it with no
        // key and it would halt.
        dev.chimera.runtime.ChimeraEngineGate.requireLicense();
        // Self-protected build: the packaged attach agent (chimera/attach/agent.jar) decrypts
        // CHENC1 classes at define time; without it the first class load hits raw ciphertext.
        // Plain builds never contain the resource, so this is a no-op there.
        if (Main.class.getResourceAsStream("/chimera/attach/agent.jar") != null) {
            dev.chimera.runtime.ChimeraAttach.install();
        }
        // Fixed exit codes (I1 GUI contract): 0 ok, 2 usage/validation, 3 build failure,
        // 4 protection bootstrap failure (thrown from ChimeraAttach via Runtime.halt).
        try {
            System.exit(run(args));
        } catch (IllegalArgumentException | IllegalStateException invalid) {
            System.err.println("[chimera] ERROR: " + invalid.getMessage());
            dev.chimera.core.BuildProgress.error(2, String.valueOf(invalid.getMessage()));
            System.exit(2);
        } catch (Throwable t) {
            System.err.println("[chimera] ERROR: " + t.getMessage());
            t.printStackTrace(System.err);
            dev.chimera.core.BuildProgress.error(3, String.valueOf(t));
            System.exit(3);
        }
    }

    static int run(String[] args) throws Exception {
        ChimeraConfig cfg = new ChimeraConfig();
        String keyHex = null;
        String keyPass = null;
        String resourceKeyHex = null;
        List<String> excludes = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case "--input", "-i" -> cfg.inputJar = Path.of(req(args, ++i, a));
                case "--output", "-o" -> cfg.outputJar = Path.of(req(args, ++i, a));
                case "--native-out" -> cfg.nativeOutDir = Path.of(req(args, ++i, a));
                case "--progress-json" -> cfg.progressJsonPath = Path.of(req(args, ++i, a));
                case "--stats-json" -> cfg.statsJsonPath = Path.of(req(args, ++i, a));
                case "--quiet" -> cfg.quiet = true;
                case "--auth-server" -> cfg.authServer = req(args, ++i, a);
                case "--auth-pubkey" -> cfg.authPubkey = req(args, ++i, a);
                case "--auth-heartbeat-ms" -> cfg.authHeartbeatMs = Long.parseLong(req(args, ++i, a));
                case "--auth-pin" -> cfg.authPin = req(args, ++i, a);
                case "--resource-key-hex" -> resourceKeyHex = req(args, ++i, a);
                case "--release" -> cfg.release = true;
                // Dev-only legacy fallback (deprecated by KI-28).
                case "--key-hex" -> keyHex = req(args, ++i, a);
                case "--key-pass" -> keyPass = req(args, ++i, a);
                case "--exclude" -> excludes.add(req(args, ++i, a));
                case "--classpath-dir" -> cfg.libraryDirs.add(Path.of(req(args, ++i, a)));
                // Accept a single jar or a path-separated list (";" on Windows, ":" elsewhere).
                case "--classpath" -> {
                    for (String part : req(args, ++i, a).split(java.io.File.pathSeparator)) {
                        if (!part.isBlank()) cfg.libraryJars.add(Path.of(part.trim()));
                    }
                }
                case "--preserve-frames" -> cfg.preserveFrames = true;
                case "--compute-frames" -> cfg.preserveFrames = false;
                case "--no-rename" -> cfg.rename = false;
                case "--no-strings" -> cfg.encryptStrings = false;
                case "--no-fragments" -> cfg.fragmentMethods = false;
                case "--no-native" -> cfg.nativeStubs = false;
                case "--no-entangle" -> cfg.entangle = false;
                case "--no-honeypot" -> cfg.honeypot = false;
                case "--no-vm" -> cfg.vm = false;
                case "--no-integrity" -> cfg.integrityManifest = false;
                // #9: HMAC key for chimera/manifest.hmac; must match the native build constant.
                case "--manifest-key" -> cfg.manifestKeyHex = req(args, ++i, a);
                case "--harden" -> cfg.harden = true;
                case "--field-init-sink" -> cfg.fieldInitSink = true;
                case "--invoke-wrapper" -> cfg.invokeWrapper = true;
                case "--watermark" -> cfg.watermark = true;
                case "--wm-license" -> {
                    cfg.watermark = true;
                    cfg.watermarkLicenseId = req(args, ++i, a);
                }
                case "--embed-dll" -> cfg.embedDllPath = Path.of(req(args, ++i, a));
                case "--payload-stealth" -> cfg.payloadStealth = true;
                case "--payload-pad" -> cfg.payloadPadBytes = Long.parseLong(req(args, ++i, a));
                case "--payload-overlay" -> {
                    cfg.payloadOverlay = true;
                    cfg.payloadDllPath = Path.of(req(args, ++i, a));
                }
                case "--verify-bytecode" -> cfg.verifyBytecode = true;
                case "--no-verify-bytecode" -> cfg.verifyBytecode = false;
                case "--auth-gate" -> cfg.authGate = true;
                case "--shuffle-members" -> cfg.shuffleMembers = true;
                case "--harden-constants" -> cfg.hardenConstants = Integer.parseInt(req(args, ++i, a));
                case "--strip-debug" -> cfg.removeDebugInfo = true;
                case "--strip-debug-signatures" -> {
                    cfg.removeDebugInfo = true;
                    cfg.removeDebugSignatures = true;
                }
                case "--rename-mixins" -> {
                    cfg.renameMixinClasses = true;
                    cfg.mixinSupport = true;
                }
                case "--flatten-packages" -> cfg.flattenPackages = true;
                case "--rename-value-classes" -> cfg.renameValueClasses = true;
                case "--rename-interfaces" -> cfg.invisibleRenameInterfaces = true;
                case "--rename-runtime" -> cfg.renameRuntimeClasses = true;
                case "--strip-tests" -> cfg.stripTests = true;
                case "--native-sink" -> cfg.nativeSink = true;
                case "--native-sink-budget" -> {
                    String budget = req(args, ++i, a);
                    cfg.nativeSinkBudget = Integer.parseInt(budget.endsWith("%")
                            ? budget.substring(0, budget.length() - 1) : budget);
                }
                case "--hidden-all" -> cfg.hiddenAll = true;
                case "--hidden-entries" -> cfg.hiddenEntries = true;
            case "--class-encrypt" -> cfg.classEncrypt = true;
                case "--encrypt-mixins" -> cfg.encryptMixins = true;
                case "--mixin-support" -> cfg.mixinSupport = true;
                case "--strip-refmap" -> {
                    cfg.mixinSupport = true;
                    cfg.stripRefmap = true;
                }
                case "--cfg" -> {
                    cfg.controlFlow = true;
                    cfg.opaquePredicates = true;
                    cfg.constantChains = true;
                }
                case "--cfg-flatten" -> cfg.controlFlow = true;
                case "--cfg-predicates" -> cfg.opaquePredicates = true;
                case "--cfg-chains" -> cfg.constantChains = true;
                case "--indy" -> cfg.indy = true;
                case "--no-indy-initializers" -> cfg.indyRewriteInitializers = false;
                case "--no-indy-special" -> cfg.indyRewriteSpecialCalls = false;
                case "--short-names" -> {
                    cfg.invisibleNaming = true;
                    cfg.invisibleShortNames = true;
                }
                case "--invisible-naming" -> cfg.invisibleNaming = true;
                case "--invisible-nul-prefix" -> {
                    cfg.invisibleNaming = true;
                    cfg.invisibleNulPrefix = true;
                }
                case "--invisible-rename-interfaces" -> {
                    cfg.invisibleNaming = true;
                    cfg.invisibleRenameInterfaces = true;
                }
                case "--no-harden-signature" -> cfg.hardenInvalidSignature = false;
                case "--no-harden-decoy" -> cfg.hardenAiDecoy = false;
                case "--no-fabric-check" -> cfg.strictFabric = false;
                case "--verbose", "-v" -> cfg.verbose = true;
                case "--help", "-h" -> { usage(); return 0; }
                default -> throw new IllegalArgumentException("unknown argument: " + a);
            }
        }
        cfg.excludes.addAll(excludes);

        // KI-28: the product ResourceKey is the primary build-time encryption key (32 bytes).
        if (resourceKeyHex == null) {
            String env = System.getenv("CHIMERA_RESOURCE_KEY_HEX");
            if (env != null && !env.isBlank()) resourceKeyHex = env;
        }
        if (!cfg.release) {
            String releaseEnv = System.getenv("CHIMERA_RELEASE");
            if (releaseEnv != null
                    && (releaseEnv.equalsIgnoreCase("1") || releaseEnv.equalsIgnoreCase("true"))) {
                cfg.release = true;
            }
        }
        if (resourceKeyHex != null) {
            String compact = resourceKeyHex.replaceAll("\\s", "");
            if (!compact.matches("[0-9a-fA-F]{64}")) {
                throw new IllegalArgumentException(
                        "--resource-key-hex must be exactly 64 hex characters (32-byte ResourceKey)");
            }
            cfg.resourceKeyMaterial = Crypto.unhex(compact);
        } else {
            // Legacy global content key: dev-only fallback, rejected by ChimeraConfig.validate()
            // when cfg.release is set.
            if (keyHex == null && keyPass == null) {
                String env = System.getenv("CHIMERA_CONTENT_KEY");
                if (env != null && !env.isBlank()) {
                    if (env.matches("[0-9a-fA-F]{16,128}")) keyHex = env;
                    else keyPass = env;
                }
            }
            if (keyHex != null) cfg.keyMaterial = Crypto.unhex(keyHex);
            else if (keyPass != null) cfg.keyMaterial = Crypto.sha256(keyPass.getBytes(StandardCharsets.UTF_8));
            else if (!cfg.release) {
                throw new IllegalArgumentException("ResourceKey required: --resource-key-hex <64 hex> "
                        + "(dev-only fallback: --key-hex, --key-pass or CHIMERA_CONTENT_KEY)");
            }
            if (cfg.keyMaterial != null && cfg.keyMaterial.length < 16) {
                throw new IllegalArgumentException("legacy key material too short (>=16 bytes)");
            }
        }

        dev.chimera.core.BuildProgress.open(cfg.progressJsonPath);
        dev.chimera.core.BuildProgress.start("0.1.0",
                String.valueOf(cfg.inputJar), String.valueOf(cfg.outputJar));
        Stats stats;
        try {
            stats = new ChimeraEngine(cfg).run();
        } catch (Throwable failure) {
            dev.chimera.core.BuildProgress.error(3, String.valueOf(failure));
            throw failure;
        }
        if (cfg.statsJsonPath != null) {
            try {
                Path parent = cfg.statsJsonPath.toAbsolutePath().getParent();
                if (parent != null) {
                    java.nio.file.Files.createDirectories(parent);
                }
                java.nio.file.Files.writeString(cfg.statsJsonPath, stats.toJson() + "\n",
                        java.nio.charset.StandardCharsets.UTF_8);
            } catch (java.io.IOException failure) {
                System.err.println("[chimera] WARNING: stats file unavailable: " + failure);
            }
        }
        dev.chimera.core.BuildProgress.stats(stats.toJson());
        dev.chimera.core.BuildProgress.done(cfg.outputJar.toAbsolutePath().toString(),
                stats.elapsedMs);
        if (!cfg.quiet) {
            System.out.println("[chimera] done: " + stats);
            System.out.println("[chimera] output: " + cfg.outputJar.toAbsolutePath());
        }
        return 0;
    }

    private static String req(String[] args, int i, String flag) {
        if (i >= args.length) throw new IllegalArgumentException(flag + " requires a value");
        return args[i];
    }

    private static void usage() {
        System.out.println("""
                Chimera obfuscator CLI
                  --input, -i <jar>        input jar
                  --output, -o <jar>       output jar
                  --native-out <dir>       write generated C++ JNI templates here
                  --progress-json <file>   I1: write NDJSON build progress (E-language GUI)
                  --stats-json <file>      I1: write the flat stats JSON after a successful build
                  --quiet                  I1: suppress the stdout summary (exit codes unchanged)
                  --resource-key-hex <hex> 32-byte product ResourceKey as 64 hex chars (KI-28; required
                                           for release builds, used to encrypt all resources)
                  --release                release build: legacy content-key fallback is rejected
                  --key-hex <hex>          DEPRECATED dev fallback: legacy global content key as hex
                  --key-pass <passphrase>  DEPRECATED dev fallback: content key passphrase (sha256)
                  --exclude <prefix>       skip classes (repeatable)
                  --compute-frames         force StackMapTable recomputation (required by control-flow
                                           transforms; needs --classpath/--classpath-dir)
                  --preserve-frames        keep original StackMapTables (only recompute max stack);
                                           required when transforms do not change control flow
                  --classpath-dir <dir>    scan a directory recursively for library jars
                                           (e.g. .minecraft/libraries) for frame/verifier input
                  --classpath <jar>        library jar for frame/hierarchy resolution (Minecraft,
                                           Fabric API, ...); repeatable. Without it ASM frame
                                           computation degrades to java/lang/Object and can emit
                                           invalid StackMapTables (VerifyError in game).
                  --no-rename              disable @ChimeraRename class/method renaming
                  --no-strings             disable string encryption
                  --no-fragments           disable @ChimeraProtected fragmentation
                  --no-native              disable @ChimeraNative stubs
                  --no-entangle            disable @ChimeraEntangle arithmetic instrumentation
                  --no-honeypot            disable Task4 semantic-pollution branches
                  --no-vm                  disable @ChimeraVM bytecode virtualization
                  --no-integrity           disable manifest.hash generation
                  --manifest-key <hex>     #9: 32-byte HMAC key (64 hex) sealing chimera/manifest.hmac;
                                           must equal the native build's -DCHIMERA_MANIFEST_KEY_HEX.
                                           Omit to skip resource authentication (logged at runtime).
                  --harden                 enable M11 structural poisoning + M12 AI decoy
                  --no-harden-signature    keep valid Signature attributes (compatibility testing)
                  --no-harden-decoy        disable the M12 AI decoy method
                  --field-init-sink        G4: sink constant field initializers out of constructors
                  --invoke-wrapper         B6: route external calls through generated wrappers
                  --watermark              embed watermark shards + per-class variant bits
                  --wm-license <id>        per-license watermark tag (implies --watermark)
                  --payload-overlay <dll>  append the encrypted CHPY overlay to a built native DLL
                  --payload-stealth        #24: disguise the --embed-dll payload (Hachimi parity):
                                           masked CHS1 blob, resource name without a .dll suffix,
                                           lib*.zip staging file with a decoy data.txt entry at
                                           load time, best-effort delete after System.load. Without
                                           it --embed-dll keeps the legacy plaintext behaviour.
                  --payload-pad <bytes>    minimum random pad appended to the stealth payload
                  --verify-bytecode        Phase B gate: load the produced jar through the JVM
                                           verifier and fail the build on VerifyError
                  --no-verify-bytecode     disable the verifier gate (dev only)
                  --auth-gate              G7: install the preLaunch activation gate + panel
                  --shuffle-members        A10: shuffle member declaration order (Mixin/record exempt)
                  --harden-constants <n>   M11: constant-pool entries injected per class (default 24)
                  --strip-debug            A9: remove SourceFile/LineNumber/LocalVariable/MethodParameters
                                           (Mixin classes exempt)
                  --strip-debug-signatures A9: also strip generic Signature attributes
                  --rename-mixins          Hachimi parity: rename Mixin classes too
                  --flatten-packages       Hachimi parity: one short package for renamed classes
                  --native-sink            B1: sink selected method bodies into native code
                  --native-sink-budget <n> B1 budget: 0 = unlimited; 1..99 = percent of the mod's
                                           methods (Hachimi band 3.5~15); >=100 = absolute method
                                           count. A trailing % is accepted ("8%").
                  --hidden-entries         S1: keep hidden class entries under their invisible
                                          names (statistics + names.txt only; no runtime define)
  --class-encrypt          S2: encrypt class bodies (CHENC1) + self-attach decrypt agent
                  --encrypt-mixins         S3': also encrypt @Mixin classes (needs --class-encrypt;
                                           Mixin reads them through the hooked Fabric launcher)
                  --mixin-support          G2: rewrite mixin config targets after renaming
                  --strip-refmap           G2: also drop mixin refmaps (implies --mixin-support)
                  --cfg                    S6: control-flow flattening + opaque predicates + constant chains
                  --cfg-flatten            S6: only control-flow flattening
                  --cfg-predicates         S6: only opaque predicates
                  --cfg-chains             S6: only numeric constant chains
                  --indy                   M10: rewrite call sites to invokedynamic + member-id table
                  --no-indy-initializers   M10: skip <init>/<clinit> bodies (conservative)
                  --no-indy-special        M10: skip invokespecial private/super call sites
                  --short-names            G1: 1-2 char class/member names (implies --invisible-naming)
                  --invisible-naming       M13: append invisible code points (U+200E family) to class
                                           and member names (Hachimi parity)
                  --invisible-nul-prefix   M13 experimental: NUL prefix on class simple names
                  --invisible-rename-interfaces  M13: also rename interfaces (breaks external impls)
                  --no-fabric-check        allow @ChimeraNative/@ChimeraVM methods to reference
                                           net.minecraft.* / net.fabricmc.* (NOT for production:
                                           these break after Fabric runtime remapping)
                  --auth-server <url>      license server base URL baked into the jar
                  --auth-pubkey <base64>   license server Ed25519 public key baked into the jar
                  --auth-heartbeat-ms <n>  client heartbeat interval (default 300000)
                  --auth-pin <base64>      SPKI SHA-256 pin of the license server certificate
                                           (self-signed certs supported; strongly recommended)
                  --verbose, -v            verbose logging
                """);
    }
}
