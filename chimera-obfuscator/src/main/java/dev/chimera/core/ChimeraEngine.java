package dev.chimera.core;

import dev.chimera.crypto.Crypto;
import dev.chimera.integrity.ManifestBuilder;
import dev.chimera.transform.EntangleTransformer;
import dev.chimera.transform.FragmentTransformer;
import dev.chimera.transform.NativeStubTransformer;
import dev.chimera.transform.PreGameCheckTransformer;
import dev.chimera.transform.RenamerTransformer;
import dev.chimera.transform.VMTransformer;
import dev.chimera.transform.StringEncryptTransformer;
import dev.chimera.transform.harden.AiDecoyTransformer;
import dev.chimera.transform.harden.StructuralPoisonTransformer;
import dev.chimera.transform.naming.InvisibleNameTransformer;
import dev.chimera.transform.indy.IndyIntegration;
import dev.chimera.transform.cfg.ConstantChain;
import dev.chimera.transform.cfg.ControlFlowFlattening;
import dev.chimera.transform.cfg.OpaquePredicate;
import dev.chimera.transform.debug.DebugInformationRemover;
import dev.chimera.transform.shuffle.MemberShuffler;
import dev.chimera.transform.init.FieldInitSink;
import dev.chimera.transform.sink.NativeSinkPlanner;
import dev.chimera.transform.sink.NativeSinkTransformer;
import dev.chimera.transform.wrap.InvokeWrapper;
import dev.chimera.transform.payload.PayloadPackager;
import dev.chimera.transform.watermark.WatermarkEmbedder;
import dev.chimera.transform.watermark.WatermarkPlan;
import dev.chimera.transform.mixinsupport.MixinSupport;
import dev.chimera.transform.hidden.HiddenSetOptions;
import dev.chimera.transform.hidden.HiddenSetPlanner;
import dev.chimera.transform.hidden.Report;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/**
 * Orchestrates the whole build: read jar -> transform classes -> generate resources -> write jar.
 */
public final class ChimeraEngine {
    private static final String[] RUNTIME_CLASSES = {
            "dev/chimera/runtime/DebugSwitches.class",
            "dev/chimera/runtime/ChimeraBuildFlags.class",
            "dev/chimera/runtime/ChimeraPreLaunch.class",
            "dev/chimera/runtime/ChimeraMainBootstrap.class",
            "dev/chimera/runtime/ChimeraActivationPanel.class",
            "dev/chimera/runtime/ChimeraActivationPanel$Activator.class",
            "dev/chimera/runtime/ChimeraActivationPanel$Status.class",
            "dev/chimera/runtime/ChimeraActivationPanel$ActivationResult.class",
            "dev/chimera/runtime/ChimeraPreLaunch$LicenseBackend.class",
            // The panel adapter. It used to be an anonymous class (ChimeraPreLaunch$1) that was
            // never registered here, so it never shipped: every unlicensed launch died at preLaunch
            // with NoClassDefFoundError before the activation panel could appear. Keep it a named
            // nested class so this entry cannot silently go stale.
            "dev/chimera/runtime/ChimeraPreLaunch$PanelActivator.class",
            "dev/chimera/runtime/ChimeraPayloadLoader.class",
            "dev/chimera/runtime/ChimeraPayloadLoader$NativeProbe.class",
            "dev/chimera/runtime/ChimeraPayloadLoader$ReflectiveProbe.class",
            "dev/chimera/runtime/ChimeraHiddenLoader.class",
            "dev/chimera/runtime/ChimeraLicenseBackend.class",
            "dev/chimera/runtime/ChimeraEmbeddedNative.class",
            "dev/chimera/runtime/ChimeraStealthLoader.class",
            // Single payload entry point (2026-10-22): every caller now goes through it, so it must
            // ship or the runtime dies with NoClassDefFoundError. This list is a hard-coded
            // whitelist - adding a runtime class without adding it here silently breaks the build.
            "dev/chimera/runtime/ChimeraPayload.class",
            // #24: the staged payload codec is called by ChimeraStealthLoader inside the
            // protected jar, so it must ship with the runtime classes (it used to be missing and
            // fail-closed halted at preLaunch with NoClassDefFoundError).
            "dev/chimera/transform/payload/StealthPayloadCodec.class",
            "dev/chimera/transform/payload/StealthPayloadCodec$Layout.class",
            "dev/chimera/runtime/ChimeraStealthLoader$LoadOp.class",
            "dev/chimera/runtime/ChimeraSessionRestorer.class",
            "dev/chimera/runtime/ChimeraV4Session.class",
            "dev/chimera/runtime/ChimeraV4Session$Result.class",
            "dev/chimera/runtime/ChimeraHiddenRegistry.class",
            "dev/chimera/runtime/HiddenNameAudit.class",
            "dev/chimera/runtime/ChimeraHiddenRegistry$Result.class",
            "dev/chimera/runtime/ChimeraRuntime.class",
            "dev/chimera/transform/indy/ChimeraBootstrap.class",
            "dev/chimera/transform/indy/MemberIdRegistry.class",
            "dev/chimera/transform/indy/CheckHook.class",
            "dev/chimera/transform/indy/CheckHook$LinkRequest.class",
            "dev/chimera/transform/indy/MemberIdRegistry$MemberKey.class",
            "dev/chimera/runtime/ChimeraVmRuntime.class",
            "dev/chimera/runtime/ChimeraTlsPin.class",
            "dev/chimera/runtime/ChimeraVmJump.class",
            "dev/chimera/runtime/ChimeraVmProbe.class",
            "dev/chimera/runtime/ChimeraAttach.class",
            "dev/chimera/runtime/ChimeraMixinDelegate.class",
            "dev/chimera/runtime/ChimeraEngineGate.class",
            "dev/chimera/probe/ChimeraSentinel.class"
    };

    /**
     * Build-time guard for the hand-written {@link #RUNTIME_CLASSES} whitelist.
     *
     * <p>This list has now caused three shipped defects. A runtime class that is not listed is
     * simply not written into the product jar, and the failure surfaces at run time as
     * {@code NoClassDefFoundError} from a code path that no licensed test ever executes:</p>
     * <ul>
     *   <li>{@code ChimeraPayload} - lost, then re-added with a comment as its tombstone;</li>
     *   <li>{@code StealthPayloadCodec} - same, "fail-closed halted at preLaunch";</li>
     *   <li>{@code ChimeraPreLaunch$1} (2026-10-22) - an <b>anonymous</b> class introduced when the
     *       activation panel gained a {@code register} action. It was never registered, so every
     *       unlicensed launch died before the panel could appear: no new customer could be
     *       onboarded at all, while every test on an already-activated machine kept passing.</li>
     * </ul>
     *
     * <p>Anonymous classes are the dangerous shape: their name ({@code X$1}) is not something a
     * human remembers to add to a whitelist, and it renumbers whenever the enclosing source changes.
     * The guard therefore fails the build when a registered class declares an anonymous inner class
     * that is not registered, and when a listed class does not exist at all.</p>
     *
     * <p>Deliberately narrow: only anonymous inner classes are enforced, because a named nested
     * class can legitimately be left out while an anonymous one cannot be reached without its
     * enclosing class.</p>
     */
    static void verifyRuntimeClasses() {
        java.util.Set<String> registered =
                new java.util.LinkedHashSet<>(java.util.Arrays.asList(RUNTIME_CLASSES));
        java.util.List<String> missingResources = new java.util.ArrayList<>();
        java.util.List<String> missingInners = new java.util.ArrayList<>();
        for (String entry : RUNTIME_CLASSES) {
            byte[] bytes;
            try {
                bytes = readOwnResource(entry);
            } catch (java.io.IOException unreadable) {
                bytes = null;
            }
            if (bytes == null) {
                missingResources.add(entry);
                continue;
            }
            try {
                // visitInnerClass also reports inner classes *referenced* from the constant pool
                // (java/lang/invoke/MethodHandles$Lookup and friends), so restrict the check to
                // inner classes this class actually declares: Outer$Something.
                final String prefix = entry.substring(0, entry.length() - ".class".length()) + "$";
                new org.objectweb.asm.ClassReader(bytes).accept(
                        new org.objectweb.asm.ClassVisitor(org.objectweb.asm.Opcodes.ASM9) {
                            @Override
                            public void visitInnerClass(String name, String outerName,
                                                        String innerName, int access) {
                                if (!name.startsWith(prefix)) {
                                    return;
                                }
                                String resource = name + ".class";
                                if (!registered.contains(resource)) {
                                    missingInners.add(resource + (innerName == null
                                            ? "  (anonymous, declared by "
                                            : "  (nested, declared by ") + entry + ")");
                                }
                            }
                        },
                        org.objectweb.asm.ClassReader.SKIP_CODE
                                | org.objectweb.asm.ClassReader.SKIP_DEBUG
                                | org.objectweb.asm.ClassReader.SKIP_FRAMES);
            } catch (RuntimeException unparseable) {
                // Not this guard's job: a malformed class will fail later with a better message.
            }
        }
        if (missingResources.isEmpty() && missingInners.isEmpty()) {
            return;
        }
        StringBuilder message = new StringBuilder(
                "RUNTIME_CLASSES is out of sync with the runtime classes:").append('\n');
        for (String item : missingResources) {
            message.append("  - listed but not found on the classpath: ").append(item).append('\n');
        }
        for (String item : missingInners) {
            message.append("  - anonymous runtime class not listed: ").append(item).append('\n');
        }
        message.append("Add the missing entries to ChimeraEngine.RUNTIME_CLASSES: a runtime class "
                + "that is not listed is silently left out of the product jar and the protected "
                + "launch dies with NoClassDefFoundError at preLaunch.");
        throw new IllegalStateException(message.toString());
    }
    /** Renames the injected runtime classes so the artifact does not reveal their purpose. */
    private static java.util.Map<String, String> runtimeRenameMap() {
        java.util.Map<String, String> map = new java.util.LinkedHashMap<>();
        int index = 0;
        for (String entry : RUNTIME_CLASSES) {
            String internal = entry.substring(0, entry.length() - ".class".length());
            map.put(internal, "q/" + runtimeToken(index++));
        }
        map.put(PreLaunchEntrypointGenerator.INTERNAL_NAME, "q/" + runtimeToken(index));
        return map;
    }

    /**
     * M10: internal names that must never be renamed, encrypted, hardened or otherwise altered by
     * later pipeline stages. The indy member table and the rewritten call sites reference these
     * classes by name at link time (BSM handles are constant-pool entries), so a rename here would
     * break every rewritten call site at runtime. The generated {@code chimera/indy/Bsm*} owners
     * come from {@link IndyIntegration} after the naming pass, which is why they must be excluded
     * in the naming pass itself via {@code config.excludes} (done in {@link ChimeraConfig} when
     * {@code --indy} is set).
     */
    static final String[] INDY_RUNTIME_PREFIXES = {
            "chimera/indy/"
    };

    private static String runtimeToken(int id) {
        StringBuilder sb = new StringBuilder();
        int value = Math.max(0, id);
        do {
            sb.append((char) ('a' + (value % 26)));
            value = value / 26 - 1;
        } while (value >= 0);
        return sb.reverse().toString();
    }

    private static byte[] remapRuntime(byte[] bytes, java.util.Map<String, String> internalMap,
                                       java.util.Map<String, String> stringMap) {
        org.objectweb.asm.commons.Remapper remapper = new org.objectweb.asm.commons.Remapper() {
            @Override
            public String map(String internalName) {
                return internalMap.getOrDefault(internalName, internalName);
            }

            @Override
            public Object mapValue(Object value) {
                if (value instanceof String text && stringMap.containsKey(text)) {
                    return stringMap.get(text);
                }
                return super.mapValue(value);
            }

            @Override
            public String mapSignature(String signature, boolean typeSignature) {
                // Structural poisoning writes deliberately invalid Signature attributes; remapping
                // them would throw. Runtime classes never appear in generic signatures, so keep
                // them byte-identical instead of parsing untrusted signatures.
                return signature;
            }
        };
        ClassWriter writer = new ClassWriter(0);
        new ClassReader(bytes).accept(
                new org.objectweb.asm.commons.ClassRemapper(writer, remapper), 0);
        return writer.toByteArray();
    }

    private static void runtimeStringNames(java.util.Map<String, String> internalMap,
                                           java.util.Map<String, String> stringMap) {
        for (java.util.Map.Entry<String, String> entry : internalMap.entrySet()) {
            stringMap.put(entry.getKey(), entry.getValue());
            stringMap.put(entry.getKey().replace('/', '.'), entry.getValue().replace('/', '.'));
        }
    }
    private final ChimeraConfig config;
    /** True when the input jar is itself a chimera artifact (bootstrap/self-protect build). */
    private boolean chimeraArtifactInput;
    private final List<Transformer> transformers = new ArrayList<>();
    /** S6 aggregates: transformers are per-class, so stats are read after the class loop. */
    private ControlFlowFlattening controlFlowFlattening;
    private OpaquePredicate opaquePredicate;
    private ConstantChain constantChain;
    private DebugInformationRemover debugInformationRemover;
    private MemberShuffler memberShuffler;
    private FieldInitSink fieldInitSink;
    private InvokeWrapper invokeWrapper;
    private NativeSinkTransformer nativeSink;
    private WatermarkPlan watermarkPlan;

    public ChimeraEngine(ChimeraConfig config) {
        this.config = config;
        // String encryption must run before the injection: injected LDC values (annotation
        // credentials) must not be encrypted, because they are evaluated before the content key
        // exists and decryptStr would poison the runtime during a valid activation.
        // G4 must see literal initializers before string encryption rewrites them.
        if (config.fieldInitSink) {
            this.fieldInitSink = new FieldInitSink();
            this.transformers.add(this.fieldInitSink);
        }
        if (config.encryptStrings) this.transformers.add(new StringEncryptTransformer());
        this.transformers.add(new PreGameCheckTransformer());
        // B6 wraps original call sites, so it runs before entangle/fragment/VM generate code.
        if (config.invokeWrapper) {
            this.invokeWrapper = new InvokeWrapper(InvokeWrapper.Options.defaults());
            this.transformers.add(this.invokeWrapper);
        }
        // S6 control-flow family: after string/PGC, before fragment/VM/native so those stages see
        // the final method bodies (recommended order: chains -> predicates -> flattening).
        if (config.constantChains) {
            this.constantChain = new ConstantChain(true, config.controlFlowMaxInstructions);
            this.transformers.add(this.constantChain);
        }
        if (config.opaquePredicates) {
            this.opaquePredicate = new OpaquePredicate(true, config.controlFlowMaxInstructions);
            this.transformers.add(this.opaquePredicate);
        }
        if (config.controlFlow) {
            this.controlFlowFlattening = new ControlFlowFlattening(true, config.controlFlowMinBlocks,
                    config.controlFlowMaxBlocks, config.controlFlowMaxInstructions);
            this.transformers.add(this.controlFlowFlattening);
        }
        if (config.entangle) this.transformers.add(new EntangleTransformer());
        if (config.fragmentMethods) this.transformers.add(new FragmentTransformer());
        if (config.nativeStubs) this.transformers.add(new NativeStubTransformer());
        // B1: the native sink is NOT a per-class transformer here; the engine runs it as a
        // whole-jar pre-pass before the indy rewrite (see run()) so the sunk bodies are removed
        // before indy would rewrite call sites inside them.
        if (config.vm) this.transformers.add(new VMTransformer());
        // A9 runs last: fragment/VM stages copy debug attributes into generated code, so stripping
        // must happen after them. Mixin classes are skipped inside the transformer.
        if (config.shuffleMembers) {
            this.memberShuffler = new MemberShuffler(true, true);
            this.transformers.add(this.memberShuffler);
        }
        if (config.removeDebugInfo) {
            this.debugInformationRemover = new DebugInformationRemover(config.removeDebugSignatures);
            this.transformers.add(this.debugInformationRemover);
        }
    }

    public Stats run() throws Exception {
        long start = System.currentTimeMillis();
        BuildProgress.stage("init", "初始化", 2);
        config.validate();
        Stats stats = new Stats();
        java.util.Map<String, String> rtMap = config.renameRuntimeClasses
                ? runtimeRenameMap() : java.util.Map.of();
        java.util.Map<String, String> rtStrings = new java.util.HashMap<>();
        runtimeStringNames(rtMap, rtStrings);

        Map<String, byte[]> classes = new LinkedHashMap<>();
        Map<String, byte[]> resources = new LinkedHashMap<>();
        int inheritedChimeraResources = 0;
        byte[] inputBytes = Files.readAllBytes(config.inputJar);

        try (ZipFile zip = new ZipFile(config.inputJar.toFile())) {
            Enumeration<? extends ZipEntry> en = zip.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
                if (e.isDirectory()) continue;
                String name = e.getName();
                if (isSignature(name) || name.equals("module-info.class") || name.startsWith("META-INF/versions/")) {
                    continue;
                }
                // Re-protection hygiene: every chimera/* entry belongs to a PREVIOUS protection run
                // (agent jar, env/auth blobs, string table + its MAC, manifest, hidden names, indy
                // table, fragment chunks, watermark shards). Copying them forward leaves the new
                // artifact with resources from a different build: the stale string table keeps the
                // old key and its MAC is missing, so the runtime fails closed on the first decrypted
                // string and a decoy NUL path crashes the game (observed on the annotated Wurst
                // fragment input, which already carried 1001 chimera/ entries).
                if (name.startsWith("chimera/")) {
                    inheritedChimeraResources++;
                    continue;
                }
                byte[] data = readAll(zip.getInputStream(e));
                if (name.endsWith(".class")) {
                    classes.put(name, data);
                    stats.classesRead++;
                    if (name.startsWith("dev/chimera/core/ChimeraEngine.class")) {
                        chimeraArtifactInput = true;
                    }
                } else {
                    resources.put(name, data);
                }
            }
        }

        if (inheritedChimeraResources > 0) {
            // Re-protecting an already protected artifact cannot work: its string table ids,
            // fragment chunks and watermark shards belong to the previous build (different keys),
            // and its classes already call decryptStr(id) for that old table. Fail fast instead of
            // shipping something that fails closed on the first decrypted string.
            throw new IllegalStateException("input already contains " + inheritedChimeraResources
                    + " chimera/ runtime resource(s): this artifact was protected before. Protect the"
                    + " original, un-obfuscated input instead (re-protection would invalidate the"
                    + " embedded string table, fragment chunks and watermark).");
        }

        // Test-only classes are dropped before the indy member table / rename plans see them,
        // otherwise the table still references classes that no longer exist in the artifact.
        if (config.stripTests) {
            classes.entrySet().removeIf(entry -> isTestClassEntry(entry.getKey()));
            stripTestMetadata(resources);
        }

        BuildProgress.stage("profile", "解析 mod 元数据", 10);
        // S5: choose which classes can be hidden before any rename changes their names.
        // Auto-derived per-mod profile: replaces hand-maintained compatibility switches.
        ModProfile modProfile = null;
        try {
            modProfile = ModProfile.fromJar(config.inputJar);
            java.nio.file.Path profileOut = config.outputJar.toAbsolutePath().getParent()
                    .resolve("mod-profile.json");
            modProfile.writeJson(profileOut);
            // Capability probing: a refmap means the mod was built with named mappings; renaming
            // mixin classes or stripping the refmap breaks Fabric's remap step.
            if (modProfile.refmapPresent) {
                if (config.renameMixinClasses) {
                    config.renameMixinClasses = false;
                    System.err.println("[chimera] auto-downgrade: refmap present -> skip mixin renaming");
                }
                if (config.stripRefmap) {
                    config.stripRefmap = false;
                    System.err.println("[chimera] auto-downgrade: refmap present -> keep refmap");
                }
            }
            System.err.println("[chimera] mod-profile: classes=" + modProfile.classCount
                    + " entrypoints=" + modProfile.entrypoints.size()
                    + " mixins=" + modProfile.mixinClasses.size()
                    + " mixinPlugins=" + modProfile.mixinPlugins.size()
                    + " aw=" + modProfile.accessWidenerClasses.size()
                    + " refmap=" + modProfile.refmapPresent
                    + " minClassVersion=" + modProfile.minClassVersion);
        } catch (Throwable profileFailure) {
            System.err.println("[chimera] WARNING: mod-profile failed: " + profileFailure);
        }
        if (modProfile != null && !modProfile.mixinPlugins.isEmpty()) {
            // A mixin config references its plugin by binary name: renaming it would break the
            // config before any protection layer matters.
            config.extraFrozenClasses.addAll(modProfile.mixinPlugins);
        }

        java.util.Set<String> plannedHidden = java.util.Collections.emptySet();
        if (config.hiddenEntries) {
            java.util.Set<String> entrypointClasses = new java.util.TreeSet<>();
            byte[] fabricMeta = resources.get("fabric.mod.json");
            if (fabricMeta != null) {
                java.util.regex.Matcher matcher = java.util.regex.Pattern
                        .compile("\"((?:[a-z_][a-z0-9_]*\\.)+[A-Za-z0-9_$]+)\"")
                        .matcher(new String(fabricMeta, StandardCharsets.UTF_8));
                while (matcher.find()) {
                    entrypointClasses.add(matcher.group(1).replace('.', '/'));
                }
            }
            if (config.hiddenAll) {
                java.util.Set<String> keep = new java.util.TreeSet<>(entrypointClasses);
                keep.addAll(mixinClassNames(config.inputJar));
                if (modProfile != null) {
                    keep.addAll(modProfile.readableClasses());
                }
                // Mixin inner classes are loaded by name even when the config only lists the
                // outer mixin: keep mixin packages and every nested mixin class readable.
                java.util.Set<String> mixinPackages = new java.util.TreeSet<>();
                for (String kept : keep) {
                    int slash = kept.lastIndexOf('/');
                    if (slash > 0) {
                        mixinPackages.add(kept.substring(0, slash));
                    }
                }
                java.util.Set<String> nestedKeep = new java.util.TreeSet<>();
                for (String name : classes.keySet()) {
                    if (!name.endsWith(".class")) {
                        continue;
                    }
                    String internal = name.substring(0, name.length() - 6);
                    int slash = internal.lastIndexOf('/');
                    if (slash > 0 && mixinPackages.contains(internal.substring(0, slash))) {
                        nestedKeep.add(internal);
                        continue;
                    }
                    String outer = internal;
                    int dollarAt = outer.lastIndexOf('$');
                    while (dollarAt > 0) {
                        outer = outer.substring(0, dollarAt);
                        if (keep.contains(outer)) {
                            nestedKeep.add(internal);
                            break;
                        }
                        dollarAt = outer.lastIndexOf('$');
                    }
                }
                keep.addAll(nestedKeep);
                // Self-healing loop: classes listed by a previous smoke run (missing at runtime)
                // stay readable in every rebuild without engine changes.
                try {
                    java.nio.file.Path keepFile = config.outputJar.toAbsolutePath().getParent()
                            .resolve("mod-profile.keep");
                    if (java.nio.file.Files.isRegularFile(keepFile)) {
                        for (String line : java.nio.file.Files.readAllLines(keepFile)) {
                            String trimmed = line.trim().replace('.', '/');
                            if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                                keep.add(trimmed);
                                System.err.println("[chimera] keep (self-heal): " + trimmed);
                            }
                        }
                    }
                } catch (Throwable ignored) {
                    // optional file
                }
                // Mixin interfaces referenced from mixin bytecode are resolved by name by the
                // Mixin runtime; they must stay readable and keep their original names.
                java.util.Set<String> frozenMixins = new java.util.TreeSet<>();
                for (String kept : keep) {
                    byte[] keptBytes = classes.get(kept + ".class");
                    if (keptBytes == null) {
                        continue;
                    }
                    for (String reference : classReferences(keptBytes)) {
                        if (keep.contains(reference) || !classes.containsKey(reference + ".class")) {
                            continue;
                        }
                        byte[] refBytes = classes.get(reference + ".class");
                        if (refBytes != null && refBytes.length >= 10
                                && (((refBytes[8] & 0xFF) << 8) | (refBytes[9] & 0xFF)) != 0
                                && ((((refBytes[8] & 0xFF) << 8) | (refBytes[9] & 0xFF))
                                        & 0x0200) != 0) {
                            frozenMixins.add(reference);
                        }
                    }
                }
                keep.addAll(frozenMixins);
                config.extraFrozenClasses.addAll(frozenMixins);
                java.util.Set<String> hidden = new java.util.TreeSet<>();
                for (String name : classes.keySet()) {
                    if (!name.endsWith(".class")) {
                        continue;
                    }
                    String internal = name.substring(0, name.length() - 6);
                    if (internal.startsWith("dev/chimera")
                            || internal.startsWith("chimera/indy")
                            || internal.startsWith("net/minecraft")
                            || internal.startsWith("net/fabricmc")
                            || internal.startsWith("com/mojang")
                            || keep.contains(internal)) {
                        continue;
                    }
                    hidden.add(internal);
                }
                plannedHidden = hidden;
            } else {
                HiddenSetOptions hiddenOptions = new HiddenSetOptions(entrypointClasses,
                        java.util.Set.of(), java.util.Set.of("dev/chimera"), true);
                Report hiddenReport = HiddenSetPlanner.plan(classes, hiddenOptions);
                plannedHidden = hiddenReport.hiddenCandidates();
            }
        }

        // M7 rename pre-pass: only @ChimeraRename classes/methods; throws (build failure) when a
        // marked element would break Fabric runtime remapping or mod loading.
        if (config.rename) {
            RenamerTransformer.Plan renamePlan = RenamerTransformer.prepare(classes, resources, config);
            if (!renamePlan.isEmpty()) {
                classes = RenamerTransformer.apply(classes, renamePlan);
                stats.renamedClasses = renamePlan.classCount();
                stats.renamedMethods = renamePlan.methodCount();
            }
        }

        // M13 invisible-character naming: whole-jar pre-pass. It must run after the M7 rename plan
        // (which validates readable original names) and before ClassPool/transforms that bake names
        // into generated code (VM programs, native templates, hidden fragments).
        java.util.Map<String, String> plannedHiddenRenames = java.util.Map.of();
        if (config.invisibleNaming) {
            InvisibleNameTransformer.Options naming = InvisibleNameTransformer.Options.defaults();
            naming.nulPrefix = config.invisibleNulPrefix;
            naming.renameInterfaces = config.invisibleRenameInterfaces;
            naming.shortClassNames = config.invisibleShortNames;
            naming.shortMemberNames = config.invisibleShortNames;
            naming.excludes = new java.util.LinkedHashSet<>(config.excludes);
            naming.excludes.addAll(config.extraFrozenClasses);
            naming.renameMixinClasses = config.renameMixinClasses;
            naming.flattenPackages = config.flattenPackages;
            naming.renameValueClasses = config.renameValueClasses;
            InvisibleNameTransformer.Mappings applied =
                    InvisibleNameTransformer.applyWithMappings(classes, resources, naming);
            plannedHiddenRenames = applied.classRenames();
            InvisibleNameTransformer.Result renamed = applied.result();
            classes = renamed.classes();
            resources = renamed.resources();
            if (config.mixinSupport) {
                MixinSupport.Plan mixinPlan = new MixinSupport.Plan();
                mixinPlan.classRenames.putAll(applied.classRenames());
                mixinPlan.memberRenames.putAll(applied.memberRenames());
                mixinPlan.stripRefmap = config.stripRefmap;
                mixinPlan.excludes.addAll(config.excludes);
                MixinSupport.Result mixin = MixinSupport.apply(classes, resources, mixinPlan);
                classes = mixin.classes();
                resources = mixin.resources();
                stats.mixinJsonRewritten = mixin.jsonRewritten();
                stats.mixinRefmapRemoved = mixin.refmapRemoved();
                stats.mixinTargetsMapped = mixin.mixinTargetsMapped();
            }
            stats.invisibleClassesRenamed = renamed.classesRenamed();
            stats.invisibleMethodsRenamed = renamed.methodsRenamed();
            stats.invisibleFieldsRenamed = renamed.fieldsRenamed();
            stats.invisibleStringsSynced = renamed.stringsSynced();
            stats.invisibleResourcesSynced = renamed.resourcesSynced();
            stats.invisibleProtectedClasses = renamed.protectedClasses();
            stats.invisibleProtectedMembers = renamed.protectedMembers();
        }

        // A5: the S3 thin-shell split (--mixin-shell + MixinShellSplitter) was removed. S3'
        // encrypts mixin classes whole and attaches the agent through an injected mixin config
        // plugin, so the shell/helper relocation has no consumer and its flag is gone.

        // B1: boolean @ChimeraPreGameCheck results must not drive security branches. This audit
        // runs before any transform and fails the build with the affected call sites.
        PreGameCheckTransformer.auditBooleanPgcSecurity(classes);

        // B1 native sink: whole-jar pre-pass, BEFORE the M10 indy rewrite.
        // Sinking removes a method body; doing it first means (a) indy never rewrites call sites
        // inside a body that is about to disappear (no wasted BSM member-table entries for a
        // native stub), and (b) the sink's C codegen sees the original INVOKE* sites, which is
        // exactly the shape the D2 compiler supports. The reverse order (indy first) is NOT
        // equivalent: indy rewrites every call site into invokedynamic, which NativeBodyCompiler
        // cannot translate, so almost every method is silently skipped (measured on
        // PrismHack-2.1-ent: 256/11022 sunk with indy-first vs 8030/8995 when the compiler sees
        // the original INVOKE* shape). Sink-first is therefore required, not merely nicer.
        if (config.nativeSink) {
            applyNativeSinkPrepass(classes, stats);
        }

        // M10 indy: rewrite call sites into invokedynamic + member-id pairs. Runs after the name
        // pre-passes (ids are derived from final owner names) and before the per-class transforms
        // that bake code into generated artifacts. Runs AFTER the sink prepass so that bodies
        // already moved to native keep their original INVOKE* shape at codegen time.
        byte[] indyMemberTable = null;
        IndyIntegration.Result indyResult = null;
        if (config.indy) {
            IndyIntegration.Options indyOptions = new IndyIntegration.Options(
                    config.indyRewriteInitializers, config.indyRewriteSpecialCalls);
            IndyIntegration.Result indy = IndyIntegration.prepare(classes, indyOptions);
            indyResult = indy;
            classes = new java.util.LinkedHashMap<>(indy.classes());
            indyMemberTable = indy.memberTable();
            stats.indyClasses = indy.stats().classesWithRewrite();
            stats.indyInvokeSites = indy.stats().invokeSites();
            stats.indyRewritten = indy.stats().rewritten();
            stats.indySkipped = indy.stats().skipped();
            stats.indyMemberEntries = indy.memberEntries();
            stats.indyMemberTableBytes = indyMemberTable == null ? 0 : indyMemberTable.length;
            stats.indyPreservedMixinClasses = indy.preservedMixinClasses();
            stats.indySkipReasons.putAll(indy.stats().skipDistribution());
            System.err.println("[chimera] indy: rewritten=" + stats.indyRewritten + "/"
                    + stats.indyInvokeSites + " sites in " + stats.indyClasses + " classes"
                    + ", mixin preserved=" + stats.indyPreservedMixinClasses
                    + ", skip=" + stats.indySkipReasons
                    + ", bsmOwners=" + indy.distinctBsmOwners()
                    + ", memberTable=" + indy.memberEntries() + "e/" + indyMemberTable.length + "B");
        }

        ClassPool pool = new ClassPool(classes);
        // Phase 0 (C-15): release builds fail closed when frame computation cannot resolve a type
        // instead of emitting StackMapTables degraded to java/lang/Object (VerifyError in game).
        pool.setStrictHierarchy(config.release);
        for (Path libraryDir : config.libraryDirs) {
            List<Path> jars;
            try (java.util.stream.Stream<Path> stream = java.nio.file.Files.walk(libraryDir)) {
                jars = stream.filter(java.nio.file.Files::isRegularFile)
                        .filter(p -> p.toString().endsWith(".jar"))
                        .sorted()
                        .toList();
            }
            for (Path jar : jars) {
                config.libraryJars.add(jar);
            }
        }
        for (Path library : config.libraryJars) {
            try (ZipFile z = new ZipFile(library.toFile())) {
                Enumeration<? extends ZipEntry> le = z.entries();
                while (le.hasMoreElements()) {
                    ZipEntry e = le.nextElement();
                    if (e.isDirectory() || !e.getName().endsWith(".class")) {
                        continue;
                    }
                    pool.addClassBytes(e.getName(), readAll(z.getInputStream(e)));
                }
            }
        }
        // The injected runtime classes are hierarchy inputs for frame computation even though they
        // are only written into the output jar after the transform phase.
        verifyRuntimeClasses();
        for (String runtimeClass : RUNTIME_CLASSES) {
            byte[] bytes = readOwnResource(runtimeClass);
            if (bytes == null) {
                continue;
            }
            String path = runtimeClass;
            if (config.renameRuntimeClasses) {
                bytes = remapRuntime(bytes, rtMap, rtStrings);
                String internal = runtimeClass.substring(0, runtimeClass.length() - 6);
                path = rtMap.getOrDefault(internal, internal) + ".class";
            }
            pool.addClassBytes(path, bytes);
        }
        // M10: the indy support classes are hierarchy inputs too (rewritten classes reference the
        // Bsm owners in their constant pools).
        if (config.indy) {
            for (String supportClass : INDY_SUPPORT_CLASSES) {
                byte[] bytes = readOwnResource(supportClass);
                if (bytes != null) {
                    pool.addClassBytes(supportClass, bytes);
                }
            }
        }
        byte[] envSalt = Crypto.random(16);
        // KI-28: every encrypted resource derives from the product ResourceKey. The legacy global
        // content key survives only as an explicit dev fallback (release builds fail in validate()).
        byte[] buildKey = config.encryptionKeyMaterial();
        if (config.usesLegacyContentKey()) {
            System.err.println("[chimera] WARNING (KI-28 dev fallback): no ResourceKey supplied; "
                    + "resources are encrypted with the legacy global content key. "
                    + "Release builds must pass --resource-key-hex / resourceKeyHex.");
        }
        byte[] kek = Crypto.hkdf(buildKey,
                "chimera-kek-v1".getBytes(StandardCharsets.UTF_8),
                "kek".getBytes(StandardCharsets.UTF_8), 32);
        String buildId = Crypto.hex(Crypto.sha256(inputBytes));
        final Map<String, byte[]> generated = new LinkedHashMap<>();
        ResourceSink sink = generated::put;
        TransformContext ctx = new TransformContext(config, envSalt, kek, pool, sink, stats, buildId);

        // Watermark: per-build (or per-license) carrier shards + per-class variant bits. The plan
        // assigns bits here; the per-class loop stamps them into the class nodes below.
        if (config.watermark) {
            byte[] licenseTag = config.watermarkLicenseId == null || config.watermarkLicenseId.isBlank()
                    ? Crypto.sha256((buildId + "/watermark").getBytes(StandardCharsets.UTF_8))
                    : WatermarkEmbedder.deriveLicenseTag(config.watermarkLicenseId, envSalt);
            WatermarkEmbedder embedder = new WatermarkEmbedder(
                    config.encryptionKeyMaterial(), envSalt);
            watermarkPlan = embedder.embed(buildId, licenseTag, classes);
            watermarkPlan.writeResources(ctx.sink::put);
            stats.wmShardsWritten = watermarkPlan.resources().size();
        }

        // K: Mixin parses a target class's generic Signature with ASM's SignatureReader, which
        // throws on the deliberately-invalid signature that harden writes ("@Redirect conflict"
        // logs are harmless, but this one aborted the target's transformation). Targets therefore
        // keep valid signatures; everything else stays poisoned.
        java.util.Set<String> mixinTargetNames = config.harden
                ? dev.chimera.transform.mixinsupport.MixinSupport.mixinTargets(classes)
                : java.util.Set.of();

        Map<String, byte[]> outClasses = new LinkedHashMap<>();
        int transformTotal = Math.max(1, classes.size());
        int transformDone = 0;
        for (Map.Entry<String, byte[]> e : classes.entrySet()) {
            if ((transformDone++ & 31) == 0) {
                BuildProgress.stage("transform", "应用变换（命名/harden/indy/cfg）",
                        Math.min(58, 10 + (int) (48L * transformDone / transformTotal)));
            }
            String internalName = e.getKey().substring(0, e.getKey().length() - ".class".length());
            if (isExcluded(internalName) && !isIndyRuntime(internalName)) {
                // drop pre-existing runtime classes and excluded packages from the output;
                // the generated indy Bsm owners live in an excluded (never renamed) namespace
                // but must still be written into the artifact.
                // Exception: when the input IS a chimera artifact (bootstrap/self-protect),
                // dev/chimera/** classes are the product itself - keep them in the output;
                // they are excluded from renaming/sync already and get encrypted like the rest.
                if (!chimeraArtifactInput || !internalName.startsWith("dev/chimera/")) {
                    continue;
                }
            }
            byte[] originalBytes = e.getValue();
            if (isIndyRuntime(internalName)) {
                // M10: the Bsm* bootstrap owners are indy link targets; they are emitted
                // verbatim. The naming pass never sees them (they are generated after it), and
                // harden must not poison them: an invalid Signature attribute would break the
                // class every rewritten call site needs at link time.
                outClasses.put(e.getKey(), originalBytes);
                stats.classesWritten++;
                ctx.recordClassHash(e.getKey(), Crypto.hex(Crypto.sha256(originalBytes)));
                continue;
            }
            ClassNode node = new ClassNode();
            new ClassReader(originalBytes).accept(node, ClassReader.EXPAND_FRAMES);
            // Snapshot before transforms so an untouched class can be emitted byte-for-byte with
            // its original StackMapTable instead of being re-serialised with recomputed frames.
            byte[] beforeTransform = ClassFingerprint.digest(node);
            // Control-flow shape snapshot: branch/label/try-catch/frame structure only. A class
            // whose shape survived the transformer loop (naming sync, debug strip, indy rewrite,
            // harden constant-pool poisoning) keeps its original StackMapTable; frame recomputation
            // is reserved for classes whose branch structure actually changed.
            byte[] beforeTransformShape = ClassFingerprint.shapeDigest(node);
            for (Transformer t : transformers) {
                t.transform(internalName, node, ctx);
            }
            // FRAMEWORK RULE: Mixin validates and copies mixin classes (and their inner classes)
            // into the target, so they must keep their exact structure. Structural poison adds
            // dummy methods/fields and AI decoy strings, which broke Mixin's inner-class
            // generation (measured: NoClassDefFoundError net/minecraft/class_425$GlState$<hash>
            // while the same class is fine in the unprotected baseline).
            boolean structurallyFrozen = modProfile != null
                    && modProfile.readableClasses().contains(internalName);
            if (config.harden && !structurallyFrozen) {
                boolean keepValidSignature = structurallyFrozen
                        || mixinTargetNames.contains(internalName);
                StructuralPoisonTransformer.Stats ps = StructuralPoisonTransformer.transform(
                        java.util.List.of(node),
                        new StructuralPoisonTransformer.Options(
                                config.hardenInvalidSignature && !keepValidSignature, true,
                                config.hardenDummyMethods, config.hardenConstants, "chimera/fake/"));
                stats.hardenedClasses += ps.classes();
                stats.hardenedSignatures += ps.invalidSignatures();
                stats.hardenedFakeRefs += ps.fakeRefs();
                stats.hardenedDummyMethods += ps.dummyMethods();
                stats.hardenedConstants += ps.constants();
                if (config.hardenAiDecoy) {
                    AiDecoyTransformer.Stats ds = AiDecoyTransformer.transform(
                            java.util.List.of(node),
                            new AiDecoyTransformer.Options(1, "AI_META_INSTRUCTION_BLOCK", buildId));
                    stats.hardenedDecoys += ds.injected();
                }
            }
            if (watermarkPlan != null && watermarkPlan.applyCarrier(internalName, node)) {
                stats.wmClassesCarried++;
            }
            boolean untouched = java.util.Arrays.equals(beforeTransform,
                    ClassFingerprint.digest(node));
            if (untouched && !config.harden) {
                // No transformer changed this class: keep the original bytes (and frames) verbatim.
                byte[] finalOriginal = config.renameRuntimeClasses
                        ? remapRuntime(originalBytes, rtMap, rtStrings) : originalBytes;
                outClasses.put(e.getKey(), finalOriginal);
                stats.classesWritten++;
                ctx.recordClassHash(e.getKey(), Crypto.hex(Crypto.sha256(finalOriginal)));
                continue;
            }
            // Touched classes need frames when a transform may change control flow; untouched ones
            // are copied verbatim above. --preserve-frames keeps the original table (safe for the
            // transforms that rewrite instructions without changing branch/stack shapes).
            // M10 fix (WurstTranslator VerifyError): recomputing frames needs the full external
            // hierarchy (Minecraft/Fabric/gson) in the ClassPool; without it, handler-entry merges
            // degrade to java/lang/Object ("Bad type on operand stack" at the catch entry, e.g.
            // merge(JsonParseException, Exception) with gson missing). The default-on transforms
            // (fragment/entangle/VM/native stubs) are annotation-driven and usually change nothing
            // in a third-party jar, so the config flags alone must not force recomputation. Instead
            // compare the control-flow SHAPE before/after the transformer loop: only classes whose
            // branch/label/try-catch/frame structure changed get COMPUTE_FRAMES.
            boolean controlFlowShapeChanged = !java.util.Arrays.equals(beforeTransformShape,
                    ClassFingerprint.shapeDigest(node)) || ctx.framesRequired(internalName);
            int writerFlags = (config.preserveFrames || !controlFlowShapeChanged)
                    ? ClassWriter.COMPUTE_MAXS
                    : (ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
            ClassWriter cw = new ChimeraClassWriter(writerFlags, pool);
            node.accept(cw);
            byte[] out = cw.toByteArray();
            if (config.renameRuntimeClasses) {
                out = remapRuntime(out, rtMap, rtStrings);
            }
            outClasses.put(e.getKey(), out);
            stats.classesWritten++;
            ctx.recordClassHash(e.getKey(), Crypto.hex(Crypto.sha256(out)));
        }

        // S6 aggregate counters (per-class transformers, collected once at the end).
        if (constantChain != null) {
            var cfg = constantChain.stats();
            stats.cfgConstantChains += cfg.constantChains;
            stats.cfgSkippedMixin += cfg.classesSkippedMixin;
            stats.cfgSkippedTryCatch += cfg.skippedTryCatch;
            stats.cfgSkippedUnsafe += cfg.skippedUnsupported + cfg.skippedTooLarge
                    + cfg.skippedSmall + cfg.skippedAnnotated;
        }
        if (opaquePredicate != null) {
            var cfg = opaquePredicate.stats();
            stats.cfgMethodsPredicated += cfg.methodsPredicated;
            stats.cfgSkippedMixin += cfg.classesSkippedMixin;
            stats.cfgSkippedTryCatch += cfg.skippedTryCatch;
            stats.cfgSkippedUnsafe += cfg.skippedUnsupported + cfg.skippedTooLarge
                    + cfg.skippedSmall + cfg.skippedAnnotated;
        }
        if (controlFlowFlattening != null) {
            var cfg = controlFlowFlattening.stats();
            stats.cfgMethodsFlattened += cfg.methodsFlattened;
            stats.cfgSkippedMixin += cfg.classesSkippedMixin;
            stats.cfgSkippedTryCatch += cfg.skippedTryCatch;
            stats.cfgSkippedUnsafe += cfg.skippedUnsupported + cfg.skippedTooLarge
                    + cfg.skippedSmall + cfg.skippedAnnotated;
        }

        if (indyResult != null) {
            stats.bsmVariants = indyResult.distinctBsmOwners();
        }
        if (fieldInitSink != null) {
            stats.fieldInitSunk = fieldInitSink.sunkFields();
        }
        if (invokeWrapper != null) {
            stats.invokeWrapped = invokeWrapper.stats().rewritten();
        }
        if (memberShuffler != null) {
            stats.shuffledClasses = memberShuffler.classesShuffled();
            stats.shuffledFields = memberShuffler.fieldsMoved();
            stats.shuffledMethods = memberShuffler.methodsMoved();
        }
        if (debugInformationRemover != null) {
            stats.debugClassesStripped = debugInformationRemover.classesStripped();
            stats.debugLineNumbersRemoved = debugInformationRemover.lineNumbersRemoved();
            stats.debugLocalVarsRemoved = debugInformationRemover.localVariablesRemoved();
            stats.debugClassesSkipped = debugInformationRemover.classesSkipped();
        }

        java.util.List<String> unresolvedTypes = pool.unresolvedTypes();
        if (config.release && !unresolvedTypes.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < unresolvedTypes.size() && i < 20; i++) {
                if (i > 0) sb.append(", ");
                sb.append(unresolvedTypes.get(i));
            }
            if (unresolvedTypes.size() > 20) sb.append(", ... (").append(unresolvedTypes.size()).append(" total)");
            throw new IllegalStateException(
                    "release build: frame computation could not resolve " + unresolvedTypes.size()
                            + " type(s) [" + sb + "]; pass --classpath <library jars> (Minecraft, Fabric API, "
                            + "third-party libs) or build with --preserve-frames when no control-flow "
                            + "transform is enabled");
        }

        if (indyMemberTable != null) {
            generated.put("chimera/indy/members.bin", indyMemberTable);
        }
        if (!ctx.strings().isEmpty()) {
            byte[] stringsTable = ctx.encodeStringTable();
            generated.put("chimera/strings.dat", stringsTable);
            // C-06: the ciphertext table is authenticated as a whole so tampering is detected at
            // load time, while individual strings stay lazily decrypted (no plaintext table).
            byte[] stringsMacKey = ctx.deriveItemKey(ManifestBuilder.STRINGS_KIND,
                    ManifestBuilder.STRINGS_ID);
            generated.put("chimera/strings.mac",
                    new ManifestBuilder().sealedMac(stringsTable, stringsMacKey,
                            ManifestBuilder.STRINGS_AAD));
        }
        BuildProgress.stage("transform", "应用变换（命名/harden/indy/cfg）", 60);
        byte[] classEncryptKey = null;
        ClassEncryptor.Keep classEncryptKeep = null;
        // P0-3a: kept so the agent jar can be rebuilt after encryption with the exact set of
        // encrypted class names (ciphertext-mandatory enforcement lives in the agent).
        Map<String, byte[]> agentClassesForJar = null;
        if (config.authGate) {
            String entrypointInternal = PreLaunchEntrypointGenerator.INTERNAL_NAME;
            byte[] entrypointBytes = PreLaunchEntrypointGenerator.generate();
            if (config.renameRuntimeClasses) {
                entrypointBytes = remapRuntime(entrypointBytes, rtMap, rtStrings);
                entrypointInternal = rtMap.getOrDefault(entrypointInternal, entrypointInternal);
            }
            outClasses.put(entrypointInternal + ".class", entrypointBytes);
            byte[] fabricJson = resources.get("fabric.mod.json");
            if (fabricJson != null) {
                String patched = FabricGatePatch.addPreLaunch(
                        new String(fabricJson, StandardCharsets.UTF_8));
                if (config.renameRuntimeClasses) {
                    patched = patched.replace(
                            PreLaunchEntrypointGenerator.BINARY_NAME.replace('/', '.'),
                            entrypointInternal.replace('/', '.'));
                }
                resources.put("fabric.mod.json", patched.getBytes(StandardCharsets.UTF_8));
            // Post-bootstrap main entrypoint: native sink registration + hidden class definition
            // run here, after Minecraft's registry bootstrap, instead of in preLaunch.
            String mainInternal = MainEntrypointGenerator.INTERNAL_NAME;
            byte[] mainBytes = MainEntrypointGenerator.generate();
            if (config.renameRuntimeClasses) {
                mainBytes = remapRuntime(mainBytes, rtMap, rtStrings);
                mainInternal = rtMap.getOrDefault(mainInternal, mainInternal);
            }
            outClasses.put(mainInternal + ".class", mainBytes);
            byte[] fabricJson2 = resources.get("fabric.mod.json");
            String patched2 = FabricGatePatch.addMain(
                    new String(fabricJson2, StandardCharsets.UTF_8));
            if (config.renameRuntimeClasses) {
                patched2 = patched2.replace(
                        MainEntrypointGenerator.BINARY_NAME.replace('/', '.'),
                        mainInternal.replace('/', '.'));
            }
            resources.put("fabric.mod.json", patched2.getBytes(StandardCharsets.UTF_8));
            } else {
                throw new IllegalStateException(
                        "authGate requires fabric.mod.json; refusing to build a gate that never runs");
            }
        }
        if (config.classEncrypt) {
            byte[] fabricJson = resources.get("fabric.mod.json");
            // S3': mixin config plugins are instantiated by name before Mixin reads any mixin
            // class, so they can never be ciphertext - and a config that declares one is hooked
            // with our own plugin on top (see MixinPluginBootstrap).
            java.util.Set<String> plaintextKeep = new java.util.TreeSet<>();
            if (modProfile != null) {
                plaintextKeep.addAll(modProfile.mixinPlugins);
            }
            if (config.encryptMixins) {
                if (fabricJson == null) {
                    config.encryptMixins = false;
                    System.err.println("[chimera] auto-downgrade: --encrypt-mixins needs Fabric "
                            + "input; mixins stay plaintext");
                } else {
                    dev.chimera.transform.mixin.MixinPluginBootstrap.Result mixinPlugins =
                            dev.chimera.transform.mixin.MixinPluginBootstrap.apply(resources);
                    if (mixinPlugins.patchedConfigs().isEmpty()) {
                        config.encryptMixins = false;
                        System.err.println("[chimera] auto-downgrade: no mixin config found to "
                                + "install the plugin bootstrap; mixins stay plaintext");
                    } else {
                        generated.putAll(mixinPlugins.generated());
                        plaintextKeep.addAll(mixinPlugins.originalPlugins());
                        System.err.println("[chimera] mixin encryption bootstrap: configs="
                                + mixinPlugins.patchedConfigs().size()
                                + " delegates=" + mixinPlugins.originalPlugins().size());
                    }
                }
            }
            if (fabricJson == null) {
                // Bootstrap mode: protecting a non-Fabric jar (e.g. the engine itself) has no
                // Fabric entrypoint to hook, so the packaged agent is loaded via Main's own
                // preflight instead of a preLaunch entrypoint.
                System.err.println("[chimera] class encryption enabled (non-Fabric input): "
                        + "skipping preLaunch patch");
            } else {
                outClasses.put(AttachEntrypointGenerator.INTERNAL_NAME + ".class",
                        AttachEntrypointGenerator.generate());
                // P1-1 ordering: the attach agent derives its key from the native SessionHandle, so
                // it must run *after* the licence gate installed that handle. Appending (instead of
                // prepending) keeps [gate, attach] order, which is what makes an unlicensed launch
                // halt at the gate before any key can be asked for.
                String attachPatched = FabricGatePatch.addPreLaunchEntryLast(
                        new String(fabricJson, StandardCharsets.UTF_8),
                        AttachEntrypointGenerator.BINARY_NAME);
                resources.put("fabric.mod.json", attachPatched.getBytes(StandardCharsets.UTF_8));
                if (!config.authGate) {
                    System.err.println("[chimera] WARNING: class encryption without --auth-gate: no "
                            + "SessionHandle exists at runtime, so the agent cannot derive the class "
                            + "key and the protected jar will halt (exit 4) on launch.");
                }
            }
            // Mixin reads every target's bytes during MixinProcessor.prepareMixins, which runs while
            // the FIRST preLaunch entrypoint class is being loaded - before any mod-controlled code,
            // hence before the decrypting agent can attach. An encrypted target therefore reaches
            // ASM as CHENC1 ciphertext and dies in ClassReader ("Index 1 out of bounds for length
            // 0"), and Mixin drops the mixin with only a warning. Keeping in-jar targets plaintext
            // is a rule over every mod's @Mixin annotations, not a per-class exception.
            java.util.Set<String> mixinTargets =
                    dev.chimera.transform.mixinsupport.MixinSupport.mixinTargets(outClasses);
            if (!mixinTargets.isEmpty()) {
                plaintextKeep.addAll(mixinTargets);
                System.err.println("[chimera] mixin targets kept plaintext: " + mixinTargets.size());
            }
            // P1-1: the key is never written into the artifact. Native derives the same bytes at
            // runtime from the ResourceKey inside the authorized SessionHandle (see
            // ClassKeyDerivation for the alignment contract and ClassKeyAlignmentTest for proof).
            classEncryptKey = ClassKeyDerivation.derive(buildKey);
            classEncryptKeep = ClassEncryptor.plan(config, modProfile, plannedHiddenRenames,
                    ClassEncryptor.entrypointsFromMetadata(fabricJson), plaintextKeep);
            // Bootstrap order: collect from the input map first (pre-rename, pre-harden bytes
            // - exactly what a fresh agent jar needs); fall back to the engine's own artifact
            // (the plain-build path) when the input does not contain the attach package.
            Map<String, byte[]> agentClasses = ClassEncryptor.collectAgentClasses(classes);
            if (agentClasses == null) {
                agentClasses = ClassEncryptor.collectAgentClasses();
            }
            generated.put(ClassEncryptor.AGENT_JAR_RESOURCE,
                    ClassEncryptor.buildAgentJar(agentClasses));
            agentClassesForJar = agentClasses;
            System.err.println("[chimera] class encryption enabled: keep="
                    + classEncryptKeep.exact().size() + " prefixes="
                    + classEncryptKeep.prefixes().size()
                    + (config.encryptMixins ? " mixins=encrypted" : " mixins=plaintext"));
        }
        byte[] env = encodeEnv(envSalt, buildId, !config.release);
        generated.put("chimera/env.dat", env);

        if (config.authServer != null && !config.authServer.isBlank()
                && config.authPubkey != null && !config.authPubkey.isBlank()) {
            generated.put("chimera/auth.dat", encodeAuthConfig(config));
        }

        // SECURITY (audit 2026-10-22 #3/#5): an artifact that carries a native payload is a
        // protected artifact. Its runtime classes ship with the test seams compiled out and with
        // "a missing payload is tampering" baked in, so deleting native.dat/embedded.dll or
        // calling the *ForTests seams cannot downgrade it to dev semantics. Artifacts without a
        // payload (engine unit tests, plain obfuscation) keep the seams, which is what lets the
        // release-halt tests capture halt(4) instead of killing the test JVM.
        boolean payloadEmbedded = config.embedDllPath != null;
        StringBuilder runtimeHashes = new StringBuilder("CHR1\n");
        for (String runtimeClass : RUNTIME_CLASSES) {
            byte[] bytes = readOwnResource(runtimeClass);
            if (bytes == null) {
                continue;
            }
            String path = runtimeClass;
            if (config.renameRuntimeClasses) {
                bytes = remapRuntime(bytes, rtMap, rtStrings);
                String internal = runtimeClass.substring(0, runtimeClass.length() - 6);
                path = rtMap.getOrDefault(internal, internal) + ".class";
            }
            if (payloadEmbedded) {
                bytes = RuntimeSeamPatch.apply(bytes, false, true);
            }
            generated.put(path, bytes);
            runtimeHashes.append(Crypto.hex(Crypto.sha256(bytes))).append("  ")
                    .append(path).append('\n');
        }
        // M10: the indy runtime support classes (bootstrap + member registry + link hook) are part
        // of the generated artifact, not of the input jar; they must ship plaintext (ClassEncryptor
        // keep) and keep their names (BSM handles reference them by name). They are appended to
        // the runtime hash manifest as well.
        if (config.indy) {
            for (String supportClass : INDY_SUPPORT_CLASSES) {
                byte[] bytes = readOwnResource(supportClass);
                if (bytes == null) {
                    throw new IllegalStateException(
                            "indy support class missing from build: " + supportClass);
                }
                generated.put(supportClass, bytes);
                runtimeHashes.append(Crypto.hex(Crypto.sha256(bytes))).append("  ")
                        .append(supportClass).append('\n');
            }
        }
        generated.put("chimera/runtime.hash", runtimeHashes.toString().getBytes(StandardCharsets.UTF_8));

        // Single-jar delivery: the native DLL (optionally VMProtect-protected and carrying the
        // encrypted payload overlay) travels inside the mod jar and is materialised to a temp file
        // by the runtime right before the preLaunch gate.
        if (config.embedDllPath != null) {
            if (!java.nio.file.Files.isRegularFile(config.embedDllPath)) {
                throw new IllegalArgumentException("embed-dll not found: " + config.embedDllPath);
            }
            byte[] embedded = java.nio.file.Files.readAllBytes(config.embedDllPath);
            if (config.payloadStealth) {
                // #24 payload-stealth: ship a CHS1-masked blob under a non-DLL resource name and
                // let the runtime reconstruct it through the Hachimi-shaped staging loader.
                byte[] blob = dev.chimera.transform.payload.StealthPayloadCodec.encode(
                        embedded, config.payloadPadBytes, null);
                generated.put(dev.chimera.transform.payload.StealthPayloadCodec.DEFAULT_RESOURCE_NAME,
                        blob);
                stats.payloadStealthBytes = blob.length;
            } else {
                generated.put("chimera/embedded.dll", embedded);
            }
            stats.payloadOverlaysWritten += 1;
        }

        if (config.nativeSink && nativeSink != null) {
            java.nio.file.Path sinkDir = config.nativeOutDir != null
                    ? config.nativeOutDir.toAbsolutePath()
                    : config.outputJar.toAbsolutePath().getParent().resolve("chimera-sink");
            java.nio.file.Files.createDirectories(sinkDir);
            // Functions-only unit (for linking into chimera_auth.dll via
            // build-native-auth.ps1 -SinkDir: that DLL exports its own JNI_OnLoad and calls
            // chimera_sink_register_all through CHIMERA_SINK_EXTERNAL_JNI_ONLOAD).
            java.nio.file.Files.writeString(sinkDir.resolve("chimera_sink.cpp"),
                    nativeSink.result().cppUnit(false), java.nio.charset.StandardCharsets.UTF_8);
            java.nio.file.Files.writeString(sinkDir.resolve("chimera_sink.registration.cpp"),
                    nativeSink.result().registerNativesSnippet(false),
                    java.nio.charset.StandardCharsets.UTF_8);
            // Standalone DLL unit: JNI_OnLoad registers every sunk method on load.
            java.nio.file.Files.writeString(sinkDir.resolve("chimera_sink_combined.cpp"),
                    nativeSink.result().cppUnit(true),
                    java.nio.charset.StandardCharsets.UTF_8);
            java.nio.file.Files.writeString(sinkDir.resolve("chimera_sink.manifest.txt"),
                    nativeSink.result().encodeSinkManifest(),
                    java.nio.charset.StandardCharsets.UTF_8);
            stats.nativeSinkSelected = nativeSink.stats().selected();
            stats.nativeSinkClasses = NativeSinkPlanner
                    .selectedByOwner(nativeSink.selectedMethods()).size();
            stats.nativeSinkWeight = nativeSink.selectedWeight();
            // B1 delivery: a standalone sink DLL can be compiled and passed through the same
            // --embed-dll channel as the auth DLL (or linked into it via build-native-auth.ps1
            // -SinkDir with chimera_sink_combined.cpp). Compilation happens outside the engine
            // (MinGW); emit the exact reproducible command next to the sources so the artifact is
            // self-describing even when the build host has no toolchain.
            java.nio.file.Files.writeString(sinkDir.resolve("compile-sink-dll.ps1"),
                    compileSinkDllScript(sinkDir), java.nio.charset.StandardCharsets.UTF_8);
            System.err.println("[chimera] native sink artifacts in " + sinkDir
                    + " (methods=" + stats.nativeSinkSelected
                    + " classes=" + stats.nativeSinkClasses + ")");
        }
        if (config.nativeStubs && !ctx.nativeTemplates().isEmpty() && config.nativeOutDir != null) {
            writeNativeTemplates(ctx.nativeTemplates(), config.nativeOutDir);
        }

        if (config.hiddenEntries && !plannedHidden.isEmpty()) {
            StringBuilder hiddenNames = new StringBuilder();
            for (String original : plannedHidden) {
                String renamed = plannedHiddenRenames.getOrDefault(original, original);
                if (renamed != null && !renamed.isEmpty()) {
                    hiddenNames.append(renamed).append('\n');
                }
            }
            // SECURITY (2026-10-22): this is a plaintext list of every protected class name. The
            // only runtime reader is HiddenNameAudit (a -Dchimera.hiddenAudit diagnostic), so a
            // release artifact does not need it — shipping it handed attackers the exact set of
            // classes worth attacking. Dev builds keep it so diagnostics still work.
            if (!config.release) {
                generated.put("chimera/hidden/names.txt",
                        hiddenNames.toString().getBytes(StandardCharsets.UTF_8));
            }
            System.err.println("[chimera] hidden entries kept by name: " + plannedHidden.size()
                    + (config.release ? " (names.txt withheld from release artifact)" : ""));
        }

        Files.createDirectories(config.outputJar.toAbsolutePath().getParent());
        Map<String, byte[]> all = new LinkedHashMap<>();
        all.putAll(resources);
        all.putAll(outClasses);
        all.putAll(generated);
        java.util.Set<String> encryptedClassNames = new java.util.TreeSet<>();
        if (config.classEncrypt && classEncryptKey != null && classEncryptKeep != null) {
            int encryptedCount = 0;
            // A2 (red team round 4 fix): the gate is injected here, into the bytes that get
            // encrypted, instead of by the attach agent at run time. The runtime-injected version
            // left the shipped bytes ungated, so an offline dump produced ungated classes and a
            // repack never called nativeGateCheck. Only classes that are actually encrypted are
            // gated - the plaintext runtime classes are skipped by the keep() check above, which is
            // what we want: gating them could halt before a handle exists.
            String gateRuntime = rtMap.getOrDefault(
                    "dev/chimera/runtime/ChimeraRuntime", "dev/chimera/runtime/ChimeraRuntime");
            int gatedCount = 0;
            java.util.Set<String> encryptedNames = encryptedClassNames;
            for (java.util.Map.Entry<String, byte[]> entry : all.entrySet()) {
                String entryName = entry.getKey();
                if (!entryName.endsWith(".class")) {
                    continue;
                }
                String internal = entryName.substring(0, entryName.length() - 6);
                byte[] plain = entry.getValue();
                if (classEncryptKeep.keep(internal, plain)) {
                    continue;
                }
                byte[] gated = dev.chimera.transform.gate.ClassGateInjector.inject(
                        plain, internal, gateRuntime);
                if (gated != plain) {
                    gatedCount++;
                    plain = gated;
                }
                entry.setValue(ClassEncryptor.encrypt(plain, classEncryptKey, internal));
                encryptedCount++;
                encryptedNames.add(internal);
                if ((encryptedCount & 63) == 0) {
                    BuildProgress.stage("encrypt", "加密类体",
                            Math.min(85, 60 + (int) (25L * encryptedCount
                                    / Math.max(1, all.size()))));
                }
            }
            System.err.println("[chimera] class gate baked into " + gatedCount
                    + " encrypted classes (runtime=" + gateRuntime + ")");
            stats.encryptedClasses = encryptedCount;
            // P0-3a: now that the encrypted set is known, rebuild the agent jar so it carries the
            // exact list. The agent halts the process when a listed class arrives as plaintext
            // (the "dump decrypted bodies and paste them back into the jar" attack).
            if (agentClassesForJar != null) {
                all.put(ClassEncryptor.AGENT_JAR_RESOURCE,
                        ClassEncryptor.buildAgentJar(agentClassesForJar, encryptedNames));
                System.err.println("[chimera] ciphertext-mandatory set: "
                        + encryptedNames.size() + " classes");
            }
            System.err.println("[chimera] class bodies encrypted: " + encryptedCount);
            BuildProgress.stage("encrypt", "加密类体", 85);
        }
        if (config.renameRuntimeClasses) {
            for (Map.Entry<String, byte[]> entry : generated.entrySet()) {
                if (entry.getKey().endsWith(".class")) {
                    entry.setValue(remapRuntime(entry.getValue(), rtMap, rtStrings));
                }
            }
        }
        // #9 (audit 2026-10-22): the integrity manifest is built here, not earlier, because it must
        // cover the FINAL bytes: the agent jar is rebuilt after class encryption, hidden names and
        // the watermark shards are only emitted above, and `all` is the exact entry set the zip
        // writer below produces. Previously the manifest was emitted before all of that, so
        // chimera/attach/agent.jar and every non-class resource had no coverage whatsoever.
        if (config.integrityManifest) {
            ManifestBuilder mb = new ManifestBuilder();
            java.util.Map<String, String> manifestHashes = new java.util.LinkedHashMap<>();
            // C (2026-10-22): classes are collected from `all` - the exact entry set the zip writer
            // produces - instead of ctx.classHashes(). The old path asked
            // classEncryptKeep.keep(renamedName, outClasses.get(renamedName)), and after the naming
            // pass those keys no longer matched, so EVERY runtime class (ChimeraRuntime, the gate,
            // the payload loader) fell out of the manifest. That is the whole point of the manifest:
            // the runtime classes are plaintext (they must load before the key exists) and are
            // therefore the only replaceable part of the artifact - `decryptClassBody` could be
            // patched to return dumped bytes with nothing to catch it.
            // Encrypted bodies are skipped: CHENC1 already authenticates them with AES-GCM.
            java.util.Set<String> hiddenKeys = new java.util.HashSet<>();
            if (config.hiddenEntries && !plannedHidden.isEmpty()) {
                for (String original : plannedHidden) {
                    String renamed = plannedHiddenRenames.getOrDefault(original, original);
                    hiddenKeys.add(renamed + ".class");
                }
            }
            int plaintextClassEntries = 0;
            for (java.util.Map.Entry<String, byte[]> entry : all.entrySet()) {
                String name = entry.getKey();
                if (!name.endsWith(".class") || hiddenKeys.contains(name)) {
                    continue;
                }
                String internal = name.substring(0, name.length() - 6);
                if (encryptedClassNames.contains(internal)) {
                    continue;
                }
                manifestHashes.put(name, Crypto.hex(Crypto.sha256(entry.getValue())));
                plaintextClassEntries++;
            }
            // Full coverage: every chimera/** entry that ships in this artifact, hashed over the
            // bytes the zip writer will actually store (ciphertext where applicable), except the
            // manifest records themselves.
            int resourceEntries = 0;
            for (Map.Entry<String, byte[]> entry : all.entrySet()) {
                String name = entry.getKey();
                // NOTE (2026-10-23): hashing fabric.mod.json here was tried and reverted. It broke
                // the licensed launch (exit 4 on a good artifact) and did not stop the attack it was
                // meant to stop: an attacker who rewrites the entrypoint list removes the very code
                // that performs this check, so the check never runs. Entry-point tampering is
                // therefore unpreventable from inside the mod - the honest mitigation is that the
                // resulting jar is inert (the cheat never executes), not that it is detected.
                if (!name.startsWith("chimera/") || ManifestBuilder.isReservedEntry(name)) {
                    continue;
                }
                // Per-chunk AES-GCM payloads already carry their own sealed digests (see
                // ManifestBuilder.isPerChunkEncryptedEntry); listing them would escalate a single
                // corrupted fragment into a whole-process halt for no extra detection.
                if (ManifestBuilder.isPerChunkEncryptedEntry(name)) {
                    continue;
                }
                manifestHashes.put(name, Crypto.hex(Crypto.sha256(entry.getValue())));
                resourceEntries++;
            }
            System.err.println("[chimera] manifest: " + plaintextClassEntries
                    + " plaintext classes + " + resourceEntries + " resources");
            byte[] manifest = mb.buildFull(manifestHashes);
            all.put(ManifestBuilder.MANIFEST_RESOURCE, manifest);
            // KI-28: seal the manifest digest with the ResourceKey-derived item key so the runtime
            // authenticates it through native op9 without any key entering Java.
            byte[] macKey = ctx.deriveItemKey(ManifestBuilder.MANIFEST_KIND,
                    ManifestBuilder.MANIFEST_ID);
            all.put(ManifestBuilder.MAC_RESOURCE, mb.sealedMac(manifest, macKey));
            // #9: the record that actually authenticates the manifest. The key is a compile-time
            // constant of chimera_auth.dll (-DCHIMERA_MANIFEST_KEY_HEX), so the jar carries only
            // the tag and cannot recompute it. Without the key on both sides the runtime logs that
            // resource authentication is unenforced instead of pretending it is covered.
            if (config.manifestKeyHex != null && !config.manifestKeyHex.isBlank()) {
                all.put(ManifestBuilder.HMAC_RESOURCE,
                        mb.manifestHmac(manifest, Crypto.unhex(config.manifestKeyHex.trim())));
                System.err.println("[chimera] manifest: " + manifestHashes.size()
                        + " entries (" + resourceEntries + " chimera/** resources), HMAC record emitted");
            } else {
                System.err.println("[chimera] manifest: " + manifestHashes.size()
                        + " entries (" + resourceEntries + " chimera/** resources), "
                        + "NO HMAC record (pass --manifest-key to authenticate it)");
            }
        }

        BuildProgress.stage("write", "写出 jar", 92);
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(config.outputJar))) {
            for (Map.Entry<String, byte[]> entry : all.entrySet()) {
                String name = entry.getKey();
                if (config.stripTests && isTestClassEntry(name)) {
                    continue;
                }
                String hiddenInternal = name.substring(0, name.length() - 6);
                String hiddenOriginal = hiddenInternal;
                if (!plannedHidden.contains(hiddenInternal)) {
                    for (java.util.Map.Entry<String, String> rename : plannedHiddenRenames.entrySet()) {
                        if (rename.getValue().equals(hiddenInternal)) {
                            hiddenOriginal = rename.getKey();
                            break;
                        }
                    }
                }
                if (config.hiddenEntries && isHiddenEligible(name)
                        && plannedHidden.contains(hiddenOriginal)) {
                    // S1: keep the entry under the class's real (invisible) internal name so the
                    // Fabric class loader resolves it by name. No invisible wrapping after
                    // ".class" and no native DefineClass: that mismatch was the root cause of the
                    // early-tier NoClassDefFoundError failures.
                    stats.hiddenClassEntries++;
                }
                putEntry(zos, name, entry.getValue());
            }
        }
        // Release artifacts are always verifier-gated; dev builds opt in via --verify-bytecode.
        if ((config.verifyBytecode || config.release) && !config.classEncrypt) {
            java.util.List<Path> verificationPath = new java.util.ArrayList<>(config.libraryJars);
            verificationPath.add(config.inputJar);
            java.util.List<BytecodeVerifier.Failure> failures =
                    BytecodeVerifier.verify(config.outputJar, verificationPath);
            if (!failures.isEmpty()) {
                StringBuilder message = new StringBuilder("JVM verifier rejected ")
                        .append(failures.size()).append(" class(es):");
                for (int i = 0; i < failures.size() && i < 10; i++) {
                    message.append("\n  - ").append(failures.get(i).className())
                            .append(": ").append(failures.get(i).message());
                }
                message.append("\n  hint: a rejected class usually references types outside the input jar;")
                        .append(" pass --classpath <Minecraft, Fabric API, third-party libs> so frame")
                        .append(" computation can resolve them.");
                throw new IllegalStateException(message.toString());
            }
        }
        if (config.payloadOverlay) {
            if (config.payloadDllPath == null) {
                throw new IllegalArgumentException("payloadOverlay requires payloadDllPath");
            }
            if (!java.nio.file.Files.isRegularFile(config.payloadDllPath)) {
                throw new IllegalArgumentException(
                        "payloadOverlay: DLL not found: " + config.payloadDllPath);
            }
            byte[] dll = java.nio.file.Files.readAllBytes(config.payloadDllPath);
            byte[] payload = null;
            if (config.payloadPadBytes > 0L) {
                // Pad the encrypted plaintext (not the carrier) so the on-disk file stays
                // carrier + ciphertext while the extracted image looks Hachimi-sized.
                long target = Math.max(config.payloadPadBytes, dll.length);
                payload = new byte[(int) target];
                System.arraycopy(dll, 0, payload, 0, dll.length);
                byte[] filler = dev.chimera.crypto.Crypto.random((int) Math.min(target - dll.length, 1 << 20));
                int at = dll.length;
                while (at < payload.length) {
                    int n = Math.min(filler.length, payload.length - at);
                    System.arraycopy(filler, 0, payload, at, n);
                    at += n;
                }
            }
            byte[] packed = PayloadPackager.appendTo(dll, payload,
                    config.encryptionKeyMaterial(), envSalt);
            Path packedDir = config.nativeOutDir != null
                    ? config.nativeOutDir.toAbsolutePath()
                    : config.outputJar.toAbsolutePath().getParent();
            java.nio.file.Files.createDirectories(packedDir);
            Path packedPath = packedDir.resolve(config.payloadDllPath.getFileName() + ".packed");
            java.nio.file.Files.write(packedPath, packed);
            stats.payloadOverlaysWritten = 1;
            stats.payloadOverlayBytes = packed.length;
        }
        stats.elapsedMs = System.currentTimeMillis() - start;
        return stats;
    }

    private boolean isExcluded(String internalName) {
        for (String ex : config.excludes) {
            if (internalName.equals(ex) || internalName.startsWith(ex + "/") || internalName.startsWith(ex)) return true;
        }
        return internalName.startsWith("dev/chimera/runtime/")
                // attach/probe classes are duplicated into the packaged agent jar verbatim;
        // if the body copy is hardened (renamed fields), the agent's calls fail with
        // NoSuchFieldError at agentmain time. Both copies must stay byte-identical.
                || internalName.startsWith("dev/chimera/attach/")
                || internalName.startsWith("dev/chimera/probe/");
    }

    /**
     * B1 native sink pre-pass (whole jar, before indy). Planner ranks classes by call weight
     * (in-jar incoming calls first, method count and body size as tie-signal), excludes
     * mixin/keep/dev-chimera classes (same exclusion semantics as indy and ClassEncryptor), then
     * the transformer sinks method bodies inside the allowed set only. Budget semantics:
     * 0 = unlimited; 1..99 = percent of the jar's methods; >=100 = absolute method count.
     * Failure-safe: any planner/compile error logs and skips the sink stage (build continues).
     */
    private void applyNativeSinkPrepass(Map<String, byte[]> classes, Stats stats) {
        try {
            int budget = NativeSinkPlanner.normalizeBudget(config.nativeSinkBudget);
            int maxMethods;
            int maxClasses;
            if (budget == NativeSinkPlanner.UNLIMITED) {
                maxMethods = 0;
                maxClasses = 0;
            } else if (NativeSinkPlanner.isPercentBudget(budget)) {
                int totalMethods = 0;
                for (java.util.Map.Entry<String, byte[]> entry : classes.entrySet()) {
                    if (entry.getKey() == null || !entry.getKey().endsWith(".class")) {
                        continue;
                    }
                    try {
                        org.objectweb.asm.tree.ClassNode node = new org.objectweb.asm.tree.ClassNode();
                        new ClassReader(entry.getValue()).accept(node, ClassReader.SKIP_CODE);
                        if (node.methods != null) {
                            totalMethods += node.methods.size();
                        }
                    } catch (Throwable ignored) {
                        // unreadable classes are reported by the main pipeline
                    }
                }
                maxMethods = Math.max(1, totalMethods * budget / 100);
                // Percent budget also caps the class count at ~3x the method share so the sink
                // stays concentrated on core classes (Hachimi sinks 3.5% methods in ~12% of
                // classes' top logic); 3x keeps headroom for small helpers.
                maxClasses = Math.max(1, classes.size() * Math.min(budget * 3, 100) / 100);
            } else {
                maxMethods = budget;
                maxClasses = 0;
            }
            NativeSinkTransformer.Options options = maxMethods > 0
                    ? NativeSinkTransformer.Options.withBudget(maxMethods)
                    : NativeSinkTransformer.Options.defaults();
            nativeSink = new NativeSinkTransformer(options);

            NativeSinkPlanner.Plan plan = NativeSinkPlanner.plan(
                    classes, config.excludes, maxClasses);
            if (maxClasses > 0) {
                nativeSink.restrictTo(plan.allowedClasses());
            }
            System.err.println("[chimera] native sink plan: classes=" + plan.totalClasses()
                    + " candidates=" + plan.ranked().size()
                    + " allowed=" + plan.allowedClasses().size()
                    + " (mixin=" + plan.mixinClasses() + " excluded=" + plan.excludedClasses() + ")"
                    + " budgetMethods=" + maxMethods
                    + " top=" + NativeSinkPlanner.describeTop(plan, 5));

            // Replay the sink over the class map: each touched class must be re-serialized with
            // COMPUTE_MAXS (the stub drops the Code attribute, so original frames stay valid;
            // maxStack/maxLocals of the stub are zero and a plain writer recomputes them).
            for (java.util.Map.Entry<String, byte[]> entry : classes.entrySet()) {
                String key = entry.getKey();
                byte[] bytes = entry.getValue();
                if (key == null || bytes == null || bytes.length < 10 || !key.endsWith(".class")) {
                    continue;
                }
                String internalName = key.substring(0, key.length() - 6);
                if (maxClasses > 0 && !plan.allowedClasses().contains(internalName)) {
                    continue; // gated class: untouched, no parse cost
                }
                try {
                    org.objectweb.asm.tree.ClassNode node = new org.objectweb.asm.tree.ClassNode();
                    new ClassReader(bytes).accept(node, ClassReader.EXPAND_FRAMES);
                    int before = nativeSink.stats().selected();
                    nativeSink.transform(internalName, node, sinkDummyContext(stats));
                    if (nativeSink.stats().selected() > before) {
                        // The transformer replaced bodies in this class: re-serialize it.
                        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
                        node.accept(cw);
                        classes.put(key, cw.toByteArray());
                    }
                } catch (Throwable perClassFailure) {
                    // Failure-safe: skip this class entirely (its bodies stay Java).
                    System.err.println("[chimera] native sink: skipping " + internalName
                            + ": " + perClassFailure);
                }
            }
            stats.nativeSinkSelected = nativeSink.stats().selected();
            stats.nativeSinkClasses = NativeSinkPlanner
                    .selectedByOwner(nativeSink.selectedMethods()).size();
            stats.nativeSinkWeight = nativeSink.selectedWeight();
            System.err.println("[chimera] native sink: selected=" + stats.nativeSinkSelected
                    + " classes=" + stats.nativeSinkClasses
                    + " weight=" + stats.nativeSinkWeight
                    + " skipped=" + nativeSink.stats().skipped()
                    + " reasons=" + nativeSink.stats().skippedByReason());
        } catch (Throwable planFailure) {
            // Failure-safe: a planner failure must never block the build.
            nativeSink = null;
            System.err.println("[chimera] native sink DISABLED (planner failure): " + planFailure);
        }
    }

    /** Minimal TransformContext for the sink pre-pass: only the stats counter is consumed. */
    private static TransformContext sinkDummyContext(Stats stats) {
        return new TransformContext(null, new byte[0], new byte[0], null,
                (name, data) -> { }, stats, "sink-prepass");
    }

    /** Reproducible MinGW command for the standalone sink DLL (written next to the C sources). */
    private static String compileSinkDllScript(java.nio.file.Path sinkDir) {
        String dll = sinkDir.resolve("chimera_sink.dll").toString().replace('\\', '/');
        String cpp = sinkDir.resolve("chimera_sink_combined.cpp").toString().replace('\\', '/');
        return "# Compiles the generated native sink translation unit into a standalone DLL\n"
                + "# (chimera_sink_combined.cpp carries JNI_OnLoad and self-registers on load).\n"
                + "# To link the sink into chimera_auth.dll instead, use\n"
                + "# scripts/build-native-auth.ps1 -SinkDir <this dir> (it consumes chimera_sink.cpp\n"
                + "# via CHIMERA_SINK_EXTERNAL_JNI_ONLOAD and keeps the auth DLL's own JNI_OnLoad).\n"
                + "# Adjust the g++/JDK paths if they differ on the build host.\n"
                + "$gpp = 'G:/vibecoding/chimare/tools/msys2-mingw64/mingw64/bin/g++.exe'\n"
                + "$javaHome = 'C:/Program Files/Eclipse Adoptium/jdk-21.0.12.101-hotspot'\n"
                + "& $gpp -shared -O2 -std=c++17 -ffp-contract=off `\n"
                + "    \"-I$javaHome/include\" \"-I$javaHome/include/win32\" `\n"
                + "    -o '" + dll + "' '" + cpp + "' `\n"
                + "    -static -static-libgcc -static-libstdc++\n"
                + "if ($LASTEXITCODE -ne 0) { throw \"sink DLL compilation failed\" }\n"
                + "Write-Host \"[sink] wrote " + dll + "\"\n";
    }

    /**
     * M10: the indy runtime support classes are read from the obfuscator's own artifact via
     * {@link #readOwnResource} and written into the output jar as generated entries, exactly like
     * the other {@code RUNTIME_CLASSES}. They are NOT dropped by {@link #isExcluded} because that
     * path only filters the input jar's classes; these classes never enter the input map.
     */
    private static final String[] INDY_SUPPORT_CLASSES = {
            "dev/chimera/transform/indy/ChimeraBootstrap.class",
            "dev/chimera/transform/indy/MemberIdRegistry.class",
            "dev/chimera/transform/indy/MemberIdRegistry$MemberKey.class",
            "dev/chimera/transform/indy/CheckHook.class",
            "dev/chimera/transform/indy/CheckHook$LinkRequest.class"
    };

    /** M10: generated indy bootstrap owners ({@code chimera/indy/Bsm*}) and support classes. */
    private static boolean isIndyRuntime(String internalName) {
        for (String prefix : INDY_RUNTIME_PREFIXES) {
            if (internalName.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isSignature(String name) {
        String upper = name.toUpperCase();
        return name.startsWith("META-INF/") && (upper.endsWith(".SF") || upper.endsWith(".DSA")
                || upper.endsWith(".RSA"));
    }

    private static byte[] encodeEnv(byte[] salt, String buildId, boolean devBuild) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        java.io.DataOutputStream out = new java.io.DataOutputStream(bos);
        out.writeInt(0x43485631); // CHV1
        out.writeInt(2);
        // Phase 0: bit 0 = dev build. Release builds must ignore diagnostic overrides.
        out.writeInt(devBuild ? 1 : 0);
        out.writeInt(salt.length);
        out.write(salt);
        byte[] b = buildId.getBytes(StandardCharsets.UTF_8);
        out.writeInt(b.length);
        out.write(b);
        out.flush();
        return bos.toByteArray();
    }

    /** Plaintext bootstrap config for the client license handshake (contains no secrets). */
    private static byte[] encodeAuthConfig(ChimeraConfig config) {
        StringBuilder text = new StringBuilder();
        text.append("version=2\n");
        text.append("server=").append(config.authServer.trim()).append('\n');
        text.append("pubkey=").append(config.authPubkey.trim()).append('\n');
        if (config.authPin != null && !config.authPin.isBlank()) {
            text.append("pin=").append(config.authPin.trim()).append('\n');
        }
        text.append("heartbeatMs=").append(config.authHeartbeatMs).append('\n');
        return text.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] readOwnResource(String name) throws IOException {
        try (InputStream in = ChimeraEngine.class.getClassLoader().getResourceAsStream(name)) {
            return in == null ? null : readAll(in);
        }
    }

    private static void writeNativeTemplates(List<NativeTemplate> templates, Path dir) throws IOException {
        Files.createDirectories(dir);
        for (NativeTemplate t : templates) {
            String base = NativeTemplateWriter.fileBase(t);
            Files.writeString(dir.resolve(base + ".h"),
                    NativeTemplateWriter.generateHeader(t), StandardCharsets.UTF_8);
            Files.writeString(dir.resolve(base + ".cpp"),
                    NativeTemplateWriter.generateSource(t), StandardCharsets.UTF_8);
        }
    }

    /** Mixin classes are loaded by name during preLaunch, so they can never be hidden. */
    private static java.util.Set<String> mixinClassNames(java.nio.file.Path inputJar) {
        java.util.Set<String> names = new java.util.TreeSet<>();
        try (java.util.zip.ZipFile zip = new java.util.zip.ZipFile(inputJar.toFile())) {
            java.util.Enumeration<? extends java.util.zip.ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                java.util.zip.ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                if (!name.endsWith(".class")) {
                    continue;
                }
                try (java.io.InputStream in = zip.getInputStream(entry)) {
                    org.objectweb.asm.tree.ClassNode node = new org.objectweb.asm.tree.ClassNode();
                    new ClassReader(in.readAllBytes()).accept(node,
                            org.objectweb.asm.ClassReader.SKIP_CODE | org.objectweb.asm.ClassReader.SKIP_DEBUG);
                    if (hasMixinAnnotation(node)) {
                        names.add(node.name);
                    }
                } catch (Throwable ignored) {
                    // Unreadable input classes fail later in the normal pipeline.
                }
            }
        } catch (Throwable ignored) {
            // A missing input jar is reported by the main pipeline.
        }
        return names;
    }

    private static boolean hasMixinAnnotation(org.objectweb.asm.tree.ClassNode node) {
        if (node.visibleAnnotations != null) {
            for (org.objectweb.asm.tree.AnnotationNode annotation : node.visibleAnnotations) {
                if ("Lorg/spongepowered/asm/mixin/Mixin;".equals(annotation.desc)) {
                    return true;
                }
            }
        }
        if (node.invisibleAnnotations != null) {
            for (org.objectweb.asm.tree.AnnotationNode annotation : node.invisibleAnnotations) {
                if ("Lorg/spongepowered/asm/mixin/Mixin;".equals(annotation.desc)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Removes entrypoints/mixin entries that point at stripped test classes. */
    private static void stripTestMetadata(Map<String, byte[]> resources) {
        byte[] meta = resources.get("fabric.mod.json");
        if (meta != null) {
            String json = new String(meta, StandardCharsets.UTF_8);
            // Drop JSON string items naming a stripped test class (with their separating comma).
            json = json.replaceAll("\\s*,\\s*\"net\\.wurstclient\\.test\\.[A-Za-z0-9_$]+\"", "");
            json = json.replaceAll("\"net\\.wurstclient\\.test\\.[A-Za-z0-9_$]+\"\\s*,", "");
            json = json.replaceAll("\"net\\.wurstclient\\.test\\.[A-Za-z0-9_$]+\"", "\"\"");
            resources.put("fabric.mod.json", json.getBytes(StandardCharsets.UTF_8));
        }
    }

    private static boolean isTestClassEntry(String name) {
        return name.endsWith(".class") && (name.contains("/test/") || name.startsWith("test/"));
    }

    private static boolean isHiddenEligible(String name) {
        return name.endsWith(".class")
                && !name.startsWith("dev/chimera/")
                && !name.startsWith("META-INF/")
                && !name.equals("module-info.class");
    }

    private static void putEntry(ZipOutputStream zos, String name, byte[] data) throws IOException {
        ZipEntry e = new ZipEntry(name);
        e.setTime(0L);
        // Hidden class entries are read natively (Java's zip reader drops NUL names), so they are
        // stored uncompressed: the native loader must not need a DEFLATE implementation.
        boolean hiddenName = !name.isEmpty()
                && (name.charAt(0) == 0 || name.charAt(0) == 0x200E);
        if (hiddenName) {
            java.util.zip.CRC32 crc = new java.util.zip.CRC32();
            crc.update(data);
            e.setMethod(ZipEntry.STORED);
            e.setSize(data.length);
            e.setCompressedSize(data.length);
            e.setCrc(crc.getValue());
        }
        zos.putNextEntry(e);
        zos.write(data);
        zos.closeEntry();
    }

    private static java.util.Set<String> classReferences(byte[] bytes) {
        java.util.Set<String> out = new java.util.HashSet<>();
        try {
            new org.objectweb.asm.ClassReader(bytes).accept(new org.objectweb.asm.ClassVisitor(
                    org.objectweb.asm.Opcodes.ASM9) {
                @Override
                public void visit(int version, int access, String name, String signature,
                                  String superName, String[] interfaces) {
                    addInternalRef(out, superName);
                    if (interfaces != null) {
                        for (String anInterface : interfaces) {
                            addInternalRef(out, anInterface);
                        }
                    }
                }

                @Override
                public org.objectweb.asm.FieldVisitor visitField(int access, String name,
                        String descriptor, String signature, Object value) {
                    addDescRef(out, descriptor);
                    return null;
                }

                @Override
                public org.objectweb.asm.MethodVisitor visitMethod(int access, String name,
                        String descriptor, String signature, String[] exceptions) {
                    addDescRef(out, descriptor);
                    if (exceptions != null) {
                        for (String exception : exceptions) {
                            addInternalRef(out, exception);
                        }
                    }
                    return new org.objectweb.asm.MethodVisitor(org.objectweb.asm.Opcodes.ASM9) {
                        @Override
                        public void visitTypeInsn(int opcode, String type) {
                            addInternalRef(out, type);
                        }

                        @Override
                        public void visitFieldInsn(int opcode, String owner, String fieldName,
                                                   String fieldDesc) {
                            addInternalRef(out, owner);
                            addDescRef(out, fieldDesc);
                        }

                        @Override
                        public void visitMethodInsn(int opcode, String owner, String methodName,
                                                    String methodDesc, boolean isInterface) {
                            addInternalRef(out, owner);
                            addDescRef(out, methodDesc);
                        }

                        @Override
                        public void visitInvokeDynamicInsn(String indyName, String indyDesc,
                                                           org.objectweb.asm.Handle bsm,
                                                           Object... arguments) {
                            addDescRef(out, indyDesc);
                            if (bsm != null) {
                                addDescRef(out, bsm.getDesc());
                            }
                            if (arguments != null) {
                                for (Object argument : arguments) {
                                    if (argument instanceof org.objectweb.asm.Type type) {
                                        addDescRef(out, type.getDescriptor());
                                    }
                                }
                            }
                        }

                        @Override
                        public void visitLdcInsn(Object value) {
                            if (value instanceof org.objectweb.asm.Type type) {
                                addDescRef(out, type.getDescriptor());
                            }
                        }

                        @Override
                        public void visitMultiANewArrayInsn(String desc, int dimensions) {
                            addDescRef(out, desc);
                        }
                    };
                }
            }, org.objectweb.asm.ClassReader.SKIP_DEBUG | org.objectweb.asm.ClassReader.SKIP_FRAMES);
        } catch (Throwable ignored) {
            // malformed class: no references
        }
        return out;
    }

    private static void addInternalRef(java.util.Set<String> out, String internal) {
        if (internal != null && !internal.isEmpty() && !internal.startsWith("[")) {
            out.add(internal);
        }
    }

    private static void addDescRef(java.util.Set<String> out, String descriptor) {
        if (descriptor == null) {
            return;
        }
        int index = 0;
        while ((index = descriptor.indexOf('L', index)) >= 0) {
            int end = descriptor.indexOf(';', index);
            if (end < 0) {
                break;
            }
            out.add(descriptor.substring(index + 1, end));
            index = end;
        }
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        if (needle.length == 0 || haystack.length < needle.length) {
            return -1;
        }
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
        return bos.toByteArray();
    }
}