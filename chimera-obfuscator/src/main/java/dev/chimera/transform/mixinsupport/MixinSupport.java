package dev.chimera.transform.mixinsupport;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Whole-jar Mixin metadata synchronisation for the rename pre-pass.
 *
 * <p>Class and member renames are baked into {@code mixins.json} and {@code *-refmap.json} at
 * compile time. After a rename they point at names that no longer exist, so this pass must run
 * once over the complete jar, after the rename plan exists and before any transformer bakes names
 * into generated code (VM programs, native templates, hidden fragments). The contract mirrors
 * {@code InvisibleNameTransformer.apply}: input maps are never mutated, the result contains new
 * maps, and the call is fail-closed.</p>
 *
 * <h2>What is rewritten</h2>
 * <ul>
 *   <li>mixin configs ({@code mixins.json} and any {@code *.json} with a {@code package} string
 *       plus a {@code mixins}/{@code client}/{@code server} class array): the {@code package}
 *       prefix, every class entry, and (optionally) the {@code refmap} field;</li>
 *   <li>{@code @Mixin(targets = ...)} / {@code @Mixin(value = ...)} class references inside
 *       class files;</li>
 *   <li>referenced refmaps: the whole file is deleted when {@link Plan#stripRefmap} is set,
 *       otherwise class names and member keys are mapped to their new names.</li>
 * </ul>
 *
 * <h2>Safety model</h2>
 * <ul>
 *   <li><b>Fail-closed:</b> a malformed mixin config, a malformed referenced refmap, a non-text
 *       mixin config or an unreadable class throws {@link MixinSupportException}. Nothing is
 *       returned and the input maps are unchanged, so no half-written JSON can reach the jar.</li>
 *   <li><b>No renames, no bytes changed:</b> an empty class/member plan returns the input maps
 *       unchanged and skips every rewrite (including refmap stripping).</li>
 *   <li><b>Mixin class bytes:</b> a mixin class is only re-serialized when one of its
 *       {@code @Mixin} targets is actually renamed; even then only the annotation values change,
 *       while {@code Signature}, debug information, frames and all other attributes are carried
 *       over verbatim. Classes without a mapped target keep their exact input bytes.</li>
 *   <li><b>Non-mixin JSON is untouched</b> (notably {@code fabric.mod.json}, whose
 *       {@code mixins} array lists config files rather than classes).</li>
 * </ul>
 *
 * <p>Residual risk: fully qualified mixin entries are only emitted when a single consistent
 * package rewrite is impossible (classes moved to different packages). Whether Mixin accepts
 * such entries depends on its {@code package} handling; the recommended pipeline keeps mixins in
 * one package or strips refmaps and regenerates them.</p>
 */
public final class MixinSupport {

    private MixinSupport() {
    }

    /**
     * Every class in {@code classes} that is the target of a {@code @Mixin} in the same jar.
     *
     * <p>Mixin resolves all targets while {@code MixinProcessor.prepareMixins} runs, and that
     * happens while the first {@code preLaunch} entrypoint class is being loaded - before any
     * mod-controlled code (and therefore before the decrypting agent) can run. A target whose body
     * is encrypted is handed to ASM as CHENC1 ciphertext and dies in {@code ClassReader}
     * ({@code ArrayIndexOutOfBoundsException: Index 1 out of bounds for length 0}), so the mixin is
     * silently dropped. Callers use this to keep those classes plaintext.</p>
     *
     * @param classes jar entries keyed by entry name ({@code a/b/C.class}) or internal name
     * @return internal names of in-jar mixin targets; empty when the jar declares no mixins
     */
    public static Set<String> mixinTargets(Map<String, byte[]> classes) {
        if (classes == null || classes.isEmpty()) {
            return new LinkedHashSet<>();
        }
        Set<String> present = new LinkedHashSet<>();
        for (String key : classes.keySet()) {
            if (key != null && key.endsWith(".class")) {
                present.add(key.substring(0, key.length() - ".class".length()));
            }
        }
        Set<String> targets = new LinkedHashSet<>();
        for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
            String key = entry.getKey();
            byte[] data = entry.getValue();
            if (key == null || data == null || !key.endsWith(".class")) {
                continue;
            }
            Set<String> found = new LinkedHashSet<>();
            try {
                MixinAnnotationRewriter.collectTargets(data, found);
            } catch (RuntimeException unreadable) {
                continue; // not a readable class: nothing to protect here
            }
            for (String target : found) {
                if (present.contains(target)) {
                    targets.add(target);
                }
            }
        }
        return targets;
    }

    /**
     * Rename plan for one whole-jar pass.
     *
     * <p>Class names may be internal ({@code a/b/C}) or binary ({@code a.b.C}); both forms are
     * normalised. Member keys follow the ASM convention used by the other rename plans:
     * {@code name + descriptor} ({@code run()V}, {@code value:I}) or a bare member name.</p>
     */
    public static final class Plan {

        /** Old class name to new class name (either separator style). */
        public final Map<String, String> classRenames = new LinkedHashMap<>();

        /** Old owner to ({@code member name + descriptor} or bare name) to new member name. */
        public final Map<String, Map<String, String>> memberRenames = new LinkedHashMap<>();

        /**
         * Delete the referenced refmap resources and remove their {@code refmap} fields. Safer
         * than rewriting once names changed, because a refmap always reveals the original names.
         */
        public boolean stripRefmap;

        /** Classes matching these prefixes are never mapped (same semantics as config excludes). */
        public final Set<String> excludes = new LinkedHashSet<>();

        public Plan classRename(String from, String to) {
            classRenames.put(from, to);
            return this;
        }

        public Plan memberRename(String owner, String key, String newName) {
            memberRenames.computeIfAbsent(owner, ignored -> new LinkedHashMap<>())
                    .put(key, newName);
            return this;
        }

        public Plan stripRefmap(boolean strip) {
            this.stripRefmap = strip;
            return this;
        }

        public Plan exclude(String... prefixes) {
            for (String prefix : prefixes) {
                if (prefix != null && !prefix.isEmpty()) {
                    excludes.add(prefix);
                }
            }
            return this;
        }
    }

    /**
     * Result of one pre-pass.
     *
     * @param classes           new class-entry map (input bytes preserved where untouched)
     * @param resources         new resource map (refmaps removed when stripped)
     * @param jsonRewritten     mixin config files whose bytes changed
     * @param refmapRemoved     refmap resources deleted ({@link Plan#stripRefmap})
     * @param refmapRewritten   retained refmap files whose content changed
     * @param mixinTargetsMapped class references rewritten in {@code @Mixin(targets/value)}
     *                            annotations (occurrences, not distinct classes)
     */
    public record Result(Map<String, byte[]> classes,
                         Map<String, byte[]> resources,
                         int jsonRewritten,
                         int refmapRemoved,
                         int refmapRewritten,
                         int mixinTargetsMapped) {
    }

    /**
     * Rewrites Mixin metadata in one jar.
     *
     * @param classes   jar entries ending in {@code .class}, keyed by entry name
     * @param resources all non-class jar entries
     * @param plan      rename plan (class renames, member renames, exclude prefixes)
     * @return new maps plus counters; never {@code null}
     * @throws MixinSupportException when mixin metadata cannot be parsed or rewritten safely
     */
    public static Result apply(Map<String, byte[]> classes, Map<String, byte[]> resources,
                               Plan plan) {
        if (classes == null || resources == null || plan == null) {
            throw new IllegalArgumentException("classes, resources and plan are required");
        }
        Mappings mappings = new Mappings(plan);
        if (mappings.isEmpty()) {
            return new Result(new LinkedHashMap<>(classes), new LinkedHashMap<>(resources),
                    0, 0, 0, 0);
        }

        Map<String, byte[]> outClasses = new LinkedHashMap<>();
        int targetsMapped = 0;
        for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
            String key = entry.getKey();
            byte[] data = entry.getValue();
            if (data == null || key == null || !key.endsWith(".class")) {
                outClasses.put(key, data);
                continue;
            }
            boolean needed;
            try {
                needed = MixinAnnotationRewriter.hasMappableTarget(data, mappings);
            } catch (RuntimeException e) {
                throw new MixinSupportException("cannot read class entry \"" + key + "\"", e);
            }
            if (!needed) {
                outClasses.put(key, data);
                continue;
            }
            ClassReader reader;
            ClassWriter writer;
            try {
                reader = new ClassReader(data);
                writer = new ClassWriter(reader, 0);
            } catch (RuntimeException e) {
                throw new MixinSupportException("cannot rewrite class entry \"" + key + "\"", e);
            }
            int[] mapped = {0};
            try {
                reader.accept(new MixinAnnotationRewriter(writer, mappings, mapped), 0);
            } catch (RuntimeException e) {
                throw new MixinSupportException(
                        "cannot rewrite @Mixin annotations in \"" + key + "\"", e);
            }
            if (mapped[0] == 0) {
                outClasses.put(key, data);
            } else {
                targetsMapped += mapped[0];
                outClasses.put(key, writer.toByteArray());
            }
        }

        Map<String, byte[]> rewrittenConfigs = new LinkedHashMap<>();
        Set<String> refmapsToRewrite = new LinkedHashSet<>();
        Set<String> refmapsToRemove = new LinkedHashSet<>();
        int jsonRewritten = 0;
        Set<String> resourceKeys = resources.keySet();
        for (Map.Entry<String, byte[]> entry : resources.entrySet()) {
            String key = entry.getKey();
            byte[] data = entry.getValue();
            if (data == null || key == null
                    || !key.toLowerCase(Locale.ROOT).endsWith(".json")) {
                continue;
            }
            if (!isText(data)) {
                if (looksLikeMixinName(key)) {
                    throw new MixinSupportException(
                            "mixin config \"" + key + "\" is not UTF-8 text");
                }
                continue;
            }
            Object parsed;
            try {
                parsed = Json.parse(new String(data, StandardCharsets.UTF_8));
            } catch (Json.ParseException e) {
                if (looksLikeMixinName(key)) {
                    throw new MixinSupportException(
                            "malformed mixin config \"" + key + "\"", e);
                }
                continue;
            }
            if (!MixinConfigRewriter.looksLikeMixinConfig(key, parsed)) {
                continue;
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> json = (Map<String, Object>) parsed;
            MixinConfigRewriter.Update update = MixinConfigRewriter.rewrite(
                    data, json, mappings, plan.stripRefmap, resourceKeys);
            String refmap = update.refmapPath();
            if (refmap != null) {
                String path = normalizeResourcePath(refmap);
                if (resources.containsKey(path)) {
                    if (plan.stripRefmap) {
                        refmapsToRemove.add(path);
                    } else {
                        refmapsToRewrite.add(path);
                    }
                }
            }
            if (update.changed()) {
                rewrittenConfigs.put(key, update.bytes());
                jsonRewritten++;
            }
        }

        Map<String, byte[]> outResources = new LinkedHashMap<>();
        int refmapRemoved = 0;
        int refmapRewritten = 0;
        for (Map.Entry<String, byte[]> entry : resources.entrySet()) {
            String key = entry.getKey();
            byte[] data = entry.getValue();
            if (refmapsToRemove.contains(key)) {
                refmapRemoved++;
                continue;
            }
            byte[] config = rewrittenConfigs.get(key);
            if (config != null) {
                outResources.put(key, config);
                continue;
            }
            if (refmapsToRewrite.contains(key)) {
                RefmapRewriter.Update update = RefmapRewriter.rewrite(key, data, mappings);
                if (update.changed()) {
                    refmapRewritten++;
                }
                outResources.put(key, update.bytes());
                continue;
            }
            outResources.put(key, data);
        }

        return new Result(outClasses, outResources, jsonRewritten, refmapRemoved,
                refmapRewritten, targetsMapped);
    }

    static String normalizeResourcePath(String path) {
        if (path == null) {
            return null;
        }
        String normalized = path.replace('\\', '/');
        while (normalized.startsWith("/")) {
            normalized = normalized.substring(1);
        }
        return normalized;
    }

    private static boolean looksLikeMixinName(String key) {
        int slash = key.lastIndexOf('/');
        String name = slash < 0 ? key : key.substring(slash + 1);
        return name.toLowerCase(Locale.ROOT).contains("mixin");
    }

    private static boolean isText(byte[] data) {
        for (byte value : data) {
            if (value == 0) {
                return false;
            }
        }
        return true;
    }
}
