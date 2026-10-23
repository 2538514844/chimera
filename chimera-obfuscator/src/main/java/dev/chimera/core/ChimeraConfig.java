package dev.chimera.core;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Immutable-ish configuration shared by CLI, Gradle plugin and engine. */
public final class ChimeraConfig {
    public Path inputJar;
    public Path outputJar;
    public Path nativeOutDir;
    /** I1: NDJSON progress file for the E-language GUI ({@code --progress-json}). */
    public Path progressJsonPath;
    /** I1: flat stats JSON written after a successful build ({@code --stats-json}). */
    public Path statsJsonPath;
    /** I1: suppress the human-readable stdout summary (the progress file is unaffected). */
    public boolean quiet;
    /**
     * KI-28: 32-byte product ResourceKey used to encrypt every build-time resource
     * (string table, hidden-class chunks, manifest MAC, VM blobs, ...). It is delivered by the
     * license server's {@code resource_ck} envelope at activation and never reaches Java there;
     * this field is the build-time copy obtained from {@code --resource-key-hex} /
     * {@code resourceKeyHex} / {@code CHIMERA_RESOURCE_KEY_HEX}.
     */
    public byte[] resourceKeyMaterial;

    /**
     * Release build: a 32-byte ResourceKey is mandatory; the legacy global content-key fallback is
     * rejected (KI-28 commercial red line). Dev builds may still use the legacy key with a warning.
     */
    public boolean release;

    /**
     * Legacy global content key (hex bytes or passphrase bytes). Dev-only fallback: it is used only
     * when {@link #resourceKeyMaterial} is absent. Release builds must fail closed instead.
     */
    public byte[] keyMaterial;

    /**
     * Production remap safety gate (M4 P0): reject {@code @ChimeraNative}/{@code @ChimeraVM}
     * methods whose descriptor or body references Minecraft/Fabric classes. Such references
     * break after Fabric's runtime remapping ({@code NoClassDefFoundError} in game).
     */
    public boolean strictFabric = true;
    /** License server base URL baked into the protected jar as {@code /chimera/auth.dat}. */
    public String authServer;
    /** Base64 X.509-free Ed25519 public key of the license server (32 bytes, base64). */
    public String authPubkey;
    /** Client heartbeat interval in milliseconds (default 5 minutes). */
    public long authHeartbeatMs = 300_000L;
    /** Optional base64 SPKI SHA-256 pin of the license server certificate (self-signed supported). */
    public String authPin;

    /**
     * M7: rename classes/methods marked with {@code @ChimeraRename}. The build fails when a
     * marked element is unsafe for Fabric (Minecraft/Fabric types, Mixin, entrypoint JSON).
     */
    public boolean rename = true;
    public boolean encryptStrings = true;
    public boolean fragmentMethods = true;
    public boolean nativeStubs = true;
    public boolean entangle = true;
    public boolean honeypot = true;
    public int honeypotMaxMethodBytes = 8192;
    public int honeypotMaxInstructions = 200;
    public boolean vm = true;
    public boolean integrityManifest = true;
    /**
     * #9: 32-byte HMAC key (64 hex chars) for {@code chimera/manifest.hmac}. It must be the same
     * value the shipped native library was compiled with
     * ({@code build-native-auth.ps1 -ManifestKeyHex}); the key itself never enters the artifact.
     * Null/blank means "no HMAC record" - the runtime then logs that resource authentication is
     * unenforced rather than silently claiming coverage.
     */
    public String manifestKeyHex;
    /** M11: structural poisoning (invalid Signature + fake cp refs + junk methods + cp bloat). */
    public boolean harden = false;
    public boolean hardenInvalidSignature = true;
    public int hardenDummyMethods = 8;
    public int hardenConstants = 24;
    /** M12: AI decoy strings (one decoy method per class). */
    public boolean hardenAiDecoy = true;
    /** M13: invisible-character naming (U+200E family) for classes and members. */
    public boolean invisibleNaming = false;
    /** M13 experimental: NUL prefix on class simple names (Hachimi jar entries). */
    public boolean invisibleNulPrefix = false;
    /** M13: also rename interfaces (breaks external implementors; off by default). */
    public boolean invisibleRenameInterfaces = false;
    /** G1: 1-2 character class/member names (original names not kept); implies invisibleNaming. */
    public boolean invisibleShortNames = false;
    /** Hachimi parity: rename Mixin classes (mixin configs are rewritten afterwards). */
    public boolean renameMixinClasses = false;
    /** Hachimi parity: put renamed classes in one short package instead of keeping originals. */
    public boolean flattenPackages = false;
    /** Hachimi parity: also rename enum/record/annotation classes. */
    public boolean renameValueClasses = false;
    /** M10: rewrite call sites into invokedynamic through the Chimera bootstrap. */
    public boolean indy = false;
    /** M10: also rewrite call sites inside {@code <init>}/{@code <clinit>} bodies. */
    public boolean indyRewriteInitializers = true;
    /** M10: also rewrite {@code invokespecial} private/super call sites. */
    public boolean indyRewriteSpecialCalls = true;    /** S6: control-flow flattening (basic blocks + table switch dispatcher). */
    public boolean controlFlow = false;
    public int controlFlowMinBlocks = 3;
    public int controlFlowMaxBlocks = 512;
    public int controlFlowMaxInstructions = 2000;
    /** S6: opaque predicates (always-true/false dead branches). */
    public boolean opaquePredicates = false;
    /** S6: numeric constant chains (XOR splitting). */
    public boolean constantChains = false;
    /** S6/A9: strip SourceFile/LineNumberTable/LocalVariableTable/MethodParameters (Mixin exempt). */
    public boolean removeDebugInfo = false;
    /** S6/A9: also strip generic Signature attributes from non-Mixin classes. */
    public boolean removeDebugSignatures = false;
    /** A10: shuffle member declaration order (Mixin/record/enum/interface exempt). */
    public boolean shuffleMembers = false;
    /** G7: install the preLaunch activation gate (requires the v4 license backend wiring). */
    public boolean authGate = false;
    /** Phase B gate: run the JVM verifier over the produced jar and fail on VerifyError. */
    public boolean verifyBytecode = false;
    /** S6/G4: sink constant field initializers out of constructors. */
    public boolean fieldInitSink = false;
    /** S6/B6: route external calls through generated wrapper methods. */
    public boolean invokeWrapper = false;
    /** Watermark: embed per-build (or per-license) watermark carrier + variant bits. */
    public boolean watermark = false;
    public String watermarkLicenseId;
    /** S5: append an encrypted CHPY overlay to a built native DLL. */
    public boolean payloadOverlay = false;
    public long payloadPadBytes = 0L;
    public java.nio.file.Path embedDllPath;
    /**
     * S5/#24: disguise the embedded DLL (Hachimi parity). With this flag the engine embeds a
     * CHS1-masked blob under a resource name without a {@code .dll} suffix and the runtime
     * materialises it through the Hachimi-shaped staging loader instead of the plain extractor.
     * Off (= plain {@code --embed-dll}) the legacy plaintext behaviour is preserved.
     */
    public boolean payloadStealth = false;
    /** G2: rewrite mixin config JSON target names after renaming and optionally drop refmaps. */
    public boolean mixinSupport = false;
    /** S5: rename class entries to NUL-prefixed invisible names and define them at preLaunch. */
    public boolean hiddenEntries = false;
    public boolean hiddenAll = false;
    /** S2: encrypt class bodies (CHENC1) and self-attach the decrypting agent at preLaunch. */
    public boolean classEncrypt = false;
    /**
     * S3' (stronger than the thin-shell split): also encrypt @Mixin classes. Mixin never defines
     * them - it reads their bytes through {@code FabricLauncher.getClassByteArray(name, true)},
     * which the attach agent already decrypts - so the whole mixin body can stay ciphertext on
     * disk instead of being split into plaintext shells plus encrypted helpers.
     */
    public boolean encryptMixins = false;
    /** Bootstrap mode: keep the manifest Main-Class plaintext when encrypting a non-Fabric jar. */
    public boolean mainClassKeep = true;
    public java.util.Set<String> extraFrozenClasses = new java.util.TreeSet<>();
    /** B1: sink selected method bodies into native code (D2 compiler). */
    public boolean nativeSink = false;
    /**
     * B1 budget for {@link #nativeSink}: {@code 0} = unlimited (transformer defaults),
     * {@code 1..99} = percentage of the mod's non-mixin, non-excluded methods
     * (Hachimi reference band: 3.5%~15%), {@code >=100} = absolute max method count.
     */
    public int nativeSinkBudget = 0;
    /** Drop test-only classes (e.g. net/wurstclient/test/**) from the artifact. */
    public boolean stripTests = false;
    /** Rename the injected Chimera runtime classes (entrypoint is patched accordingly). */
    public boolean renameRuntimeClasses = false;
    public boolean stripRefmap = false;
    public java.nio.file.Path payloadDllPath;
    public boolean verbose = false;

    public final List<String> excludes = new ArrayList<>();
    /** Library jars used only for class-hierarchy/frame computation (Minecraft, Fabric, JDK libs). */
    public final List<java.nio.file.Path> libraryJars = new ArrayList<>();
    /** Directories scanned recursively for library jars (Minecraft {@code libraries/}, loader deps). */
    public final List<java.nio.file.Path> libraryDirs = new ArrayList<>();
    /**
     * Preserve the original StackMapTable and only recompute max stack/locals. Required for
     * transforms that do not change control flow on Fabric classes whose hierarchy is only
     * partially available; ASM COMPUTE_FRAMES otherwise degrades to java/lang/Object and emits
     * invalid frames (VerifyError at game start).
     */
    public boolean preserveFrames = false;

    /** Key actually used for build-time resource encryption (ResourceKey, dev fallback otherwise). */
    public byte[] encryptionKeyMaterial() {
        return resourceKeyMaterial != null ? resourceKeyMaterial : keyMaterial;
    }

    /** True when no ResourceKey was supplied and resources fall back to the legacy content key. */
    public boolean usesLegacyContentKey() {
        return resourceKeyMaterial == null;
    }

    public void validate() {
        if (inputJar == null) throw new IllegalArgumentException("inputJar is required");
        if (outputJar == null) throw new IllegalArgumentException("outputJar is required");
        if (resourceKeyMaterial != null && resourceKeyMaterial.length != 32) {
            throw new IllegalArgumentException(
                    "resourceKeyMaterial must be exactly 32 bytes (got " + resourceKeyMaterial.length + ")");
        }
        if (release && resourceKeyMaterial == null) {
            throw new IllegalArgumentException(
                    "release build requires a 32-byte ResourceKey: pass --resource-key-hex <64 hex> (CLI), "
                            + "resourceKeyHex (Gradle) or CHIMERA_RESOURCE_KEY_HEX; the legacy content-key "
                            + "fallback is dev-only (KI-28)");
        }
        if (encryptionKeyMaterial() == null || encryptionKeyMaterial().length == 0) {
            throw new IllegalArgumentException(
                    "ResourceKey is required: pass --resource-key-hex <64 hex> or resourceKeyHex "
                            + "(dev builds may fall back to keyMaterial/contentKey)");
        }
        if (usesLegacyContentKey() && keyMaterial != null && keyMaterial.length < 16) {
            throw new IllegalArgumentException("legacy key material too short (>=16 bytes)");
        }
        if (payloadStealth && embedDllPath == null) {
            throw new IllegalArgumentException(
                    "--payload-stealth requires --embed-dll <dll> (it disguises the embedded DLL)");
        }
        if (indy) {
            // M10: the generated chimera/indy/Bsm* bootstrap owners and the rewritten call sites
            // reference that namespace by name (indy BSM handles are constant-pool entries), so
            // the invisible-naming pass must never touch it. Adding the prefix to excludes is
            // enough: InvisibleNameTransformer, ClassEncryptor keep-planning and the harden loop
            // all consult the same exclusion semantics.
            boolean covered = false;
            for (String exclude : excludes) {
                if ("chimera/indy/".equals(exclude) || "chimera/indy".equals(exclude)) {
                    covered = true;
                    break;
                }
            }
            if (!covered) {
                excludes.add("chimera/indy/");
            }
        }
        if (classEncrypt) {
            // The engine reads its attach package by canonical name (agent jar collection, attach
            // bootstrap, sentinel probe). When a self-protected engine protects anything, the
            // string constants inside its own classes must still carry the canonical names, so
            // the whole runtime namespace is excluded from renaming AND string sync.
            boolean covered = false;
            for (String exclude : excludes) {
                if ("dev/chimera/".equals(exclude) || "dev/chimera".equals(exclude)) {
                    covered = true;
                    break;
                }
            }
            if (!covered) {
                excludes.add("dev/chimera/");
            }
        }
        // Never rename/relocate classes that live in the Minecraft or Fabric namespaces: mods
        // inject helper/inner classes there (mixin-generated GlState$xxx etc.) and the game /
        // mixin runtime looks some of them up by name - renaming produced real NoClassDefFoundError
        // at runtime (PeakHack title-screen shader). Encryption/hardening still apply.
        for (String namespace : new String[]{"net/minecraft/", "net/fabricmc/", "com/mojang/"}) {
            if (!excludes.contains(namespace)) {
                excludes.add(namespace);
            }
        }
        if (release) {
            // Phase 0 (C-11): release builds must not disable the Fabric safety audit.
            if (!strictFabric) {
                throw new IllegalArgumentException(
                        "release build cannot pass --no-fabric-check: it allows @ChimeraNative/@ChimeraVM "
                                + "members to reference net.minecraft.* / net.fabricmc.* and breaks after "
                                + "Fabric runtime remapping");
            }
            boolean controlFlow = vm || fragmentMethods || entangle || honeypot;
            if (controlFlow && preserveFrames) {
                throw new IllegalArgumentException(
                        "release build: vm/fragments/entangle/honeypot rewrite control flow, so the original "
                                + "StackMapTable is stale; drop --preserve-frames and pass --classpath "
                                + "<minecraft+fabric jars> for frame computation");
            }
            // Phase B: release builds always run the JVM verifier gate (ChimeraEngine forces it
            // for release artifacts); nothing to validate here beyond the flag being droppable.
            // Frame hierarchy is enforced during the build (ClassPool strict mode): a release
            // build fails as soon as frame computation needs a type it cannot resolve.
        }
    }
}
