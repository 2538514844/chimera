package dev.chimera.transform.indy;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.ClassNode;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * M10 integration facade: one call produces the rewritten classes, the runtime member-id table
 * (consumed by {@link MemberIdRegistry#loadMemberTable(byte[], ClassLoader)}) and the rewrite/skip
 * statistics needed by the engine wiring.
 *
 * <p>Proposed engine contract (Lead wires it, this class does not touch ChimeraEngine/Config):</p>
 * <pre>
 *   ChimeraConfig.indy          boolean (default off; release opt-in)
 *   IndyIntegration.Options     rewriteInitializers / rewriteSpecialCalls
 *   IndyIntegration.prepare(classes, options) -> Result
 *   Result.classes()            rewritten class map (Mixin entries byte-identical to input);
 *                               generated BSM owners are included so the existing engine packages
 *                               them without extra wiring
 *   Result.extraClasses()       generated chimera/indy/Bsm0..Bsm15 classes by resource entry name
 *   Result.distinctBsmOwners()  number of generated BSM owners actually referenced (G8)
 *   Result.memberTable()        CHMI table bytes -> MemberIdRegistry.loadMemberTable(table, loader)
 *   Result.stats()              IndyDispatchTransformer.Stats (call/field-site/member counters)
 * </pre>
 *
 * <p>Runtime requirements (integration phase): {@code ChimeraBootstrap}, {@code MemberIdRegistry},
 * {@code CheckHook} and the CHMI table must be present in the protected jar BEFORE any rewritten
 * class is linked, and the table must be loaded with the protected class loader. Without that the
 * bootstrap fails closed ({@link BootstrapMethodError}), never silently falls back.</p>
 */
public final class IndyIntegration {

    /**
     * Integration options; defaults are aggressive (M10 completion target). {@code disperseBsm}
     * enables the G8 rotation across the generated {@code chimera/indy/Bsm0..Bsm15} owners; the
     * two-argument constructor keeps the existing engine call site source compatible and enables
     * dispersion by default.
     */
    public record Options(boolean rewriteInitializers, boolean rewriteSpecialCalls,
                          boolean disperseBsm) {
        /** Original M10 behaviour (only static/virtual/interface outside initializers). */
        public static final Options CONSERVATIVE = new Options(false, false, true);
        /** Rewrite eligible calls inside {@code <init>/<clinit>} and invokespecial calls too. */
        public static final Options AGGRESSIVE = new Options(true, true, true);

        /** Legacy source shape; BSM dispersion (G8) is on by default. */
        public Options(boolean rewriteInitializers, boolean rewriteSpecialCalls) {
            this(rewriteInitializers, rewriteSpecialCalls, true);
        }

        public static Options defaults() {
            return AGGRESSIVE;
        }
    }

    /**
     * @param classes              rewritten class map (entry name -> bytes); Mixin entries keep the
     *                             exact input bytes (Signature/debug preserved)
     * @param memberTable          CHMI table for {@link MemberIdRegistry#loadMemberTable}
     * @param stats                rewrite/skip counters
     * @param memberEntries        number of deduplicated member entries in the table
     *                             (method + field entries)
     * @param classEntries         number of deduplicated owner class entries in the table
     * @param preservedMixinClasses number of Mixin classes returned byte-identical
     * @param distinctBsmOwners    distinct generated bootstrap owners actually referenced (G8)
     * @param extraClasses         generated runtime support classes by entry name
     *                             ({@code chimera/indy/Bsm0.class}..{@code Bsm15.class}); the same
     *                             entries are also present in {@link #classes()} so the existing
     *                             engine wiring packages them without extra glue
     */
    public record Result(Map<String, byte[]> classes,
                         byte[] memberTable,
                         IndyDispatchTransformer.Stats stats,
                         int memberEntries,
                         int classEntries,
                         int preservedMixinClasses,
                         int distinctBsmOwners,
                         Map<String, byte[]> extraClasses) {
    }

    private IndyIntegration() {
    }

    /** Rewrites all supplied classes with the default (aggressive) options. */
    public static Result prepare(Map<String, byte[]> classes) {
        return prepare(classes, Options.defaults());
    }

    /**
     * Rewrites all supplied classes and builds the runtime member table. The input map is not
     * modified; a new map is returned. Mixin classes are counted and preserved byte-for-byte.
     */
    public static Result prepare(Map<String, byte[]> classes, Options options) {
        if (classes == null) {
            throw new IllegalArgumentException("classes must not be null");
        }
        Options effective = options == null ? Options.defaults() : options;
        IndyDispatchTransformer transformer = new IndyDispatchTransformer(
                new IndyDispatchTransformer.Options(
                        effective.rewriteInitializers(), effective.rewriteSpecialCalls(),
                        effective.disperseBsm()));
        Map<String, byte[]> rewritten = new LinkedHashMap<>();
        IndyDispatchTransformer.Stats total = new IndyDispatchTransformer.Stats();
        int preservedMixinClasses = 0;
        for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
            String name = entry.getKey();
            byte[] original = entry.getValue();
            if (original == null || original.length == 0) {
                continue;
            }
            ClassReader reader = new ClassReader(original);
            ClassNode node = new ClassNode();
            reader.accept(node, 0);
            // invokedynamic and MethodHandle constants require class file version 51+; old
            // third-party classes shaded into a mod must be left untouched.
            if (node.version < org.objectweb.asm.Opcodes.V1_7) {
                rewritten.put(name, original);
                continue;
            }
            total.merge(transformer.transform(node));
            if (IndyDispatchTransformer.isMixinClass(node)) {
                preservedMixinClasses++;
                rewritten.put(name, original);
                continue;
            }
            // Fresh writer (not the source-copying ClassWriter(reader, flags)): once a call site
            // is replaced, the original owner/member constants are dead and must not stay in the
            // constant pool (the engine emits untouched classes verbatim, so a copied pool would
            // leak the original call target). No frame computation is requested - instruction
            // shapes are unchanged, so the existing StackMapTables stay valid.
            ClassWriter writer = new ClassWriter(0);
            node.accept(writer);
            rewritten.put(name, writer.toByteArray());
        }
        Map<String, byte[]> extraClasses = Collections.emptyMap();
        if (effective.disperseBsm()) {
            extraClasses = BsmClassGenerator.generate();
            // Reserved namespace: generated owners win over input entries with the same name.
            // They live in classes() too, so the current engine (which only writes classes())
            // ships them without any wiring change; extraClasses makes the generated subset
            // explicit for callers that inject runtime support separately. classes() mirrors the
            // caller's key convention: engine maps use "a/B.class", test fixtures use "a/B".
            boolean entryNameKeys = false;
            for (String key : classes.keySet()) {
                if (key != null && key.endsWith(".class")) {
                    entryNameKeys = true;
                    break;
                }
            }
            for (Map.Entry<String, byte[]> generated : extraClasses.entrySet()) {
                String key = entryNameKeys ? generated.getKey()
                        : generated.getKey().substring(0,
                                generated.getKey().length() - ".class".length());
                rewritten.put(key, generated.getValue());
            }
        }
        byte[] memberTable = encodeMemberTable(total);
        return new Result(Collections.unmodifiableMap(rewritten), memberTable, total,
                total.memberEntries().size(), total.classEntries().size(), preservedMixinClasses,
                total.distinctBsmOwners(), extraClasses);
    }

    /** Encodes the deduplicated class/member ids collected by {@link IndyDispatchTransformer}. */
    public static byte[] encodeMemberTable(IndyDispatchTransformer.Stats stats) {
        if (stats == null) {
            throw new IllegalArgumentException("stats must not be null");
        }
        List<IndyDispatchTransformer.ClassEntry> classes = stats.classEntries();
        List<IndyDispatchTransformer.MemberEntry> fields = stats.fieldEntries();
        List<IndyDispatchTransformer.MemberEntry> methods = stats.methodEntries();
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream(32 + classes.size() * 32
                    + (fields.size() + methods.size()) * 64);
            DataOutputStream out = new DataOutputStream(buffer);
            out.writeInt(MemberIdRegistry.MEMBER_TABLE_MAGIC);
            out.writeInt(MemberIdRegistry.MEMBER_TABLE_VERSION);
            out.writeInt(classes.size() + fields.size() + methods.size());
            for (IndyDispatchTransformer.ClassEntry entry : classes) {
                out.writeByte(MemberIdRegistry.ENTRY_CLASS);
                out.writeLong(entry.classId());
                out.writeLong(0L);
                writeUtf(out, entry.internalName());
                writeUtf(out, "");
                writeUtf(out, "");
            }
            for (IndyDispatchTransformer.MemberEntry entry : fields) {
                out.writeByte(MemberIdRegistry.ENTRY_FIELD);
                out.writeLong(entry.classId());
                out.writeLong(entry.memberId());
                writeUtf(out, entry.owner());
                writeUtf(out, entry.name());
                writeUtf(out, entry.desc());
            }
            for (IndyDispatchTransformer.MemberEntry entry : methods) {
                out.writeByte(MemberIdRegistry.ENTRY_METHOD);
                out.writeLong(entry.classId());
                out.writeLong(entry.memberId());
                writeUtf(out, entry.owner());
                writeUtf(out, entry.name());
                writeUtf(out, entry.desc());
            }
            out.flush();
            return buffer.toByteArray();
        } catch (java.io.IOException e) {
            throw new IllegalStateException("member table encoding failed", e);
        }
    }

    private static void writeUtf(DataOutputStream out, String value) throws java.io.IOException {
        byte[] bytes = value.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        out.writeInt(bytes.length);
        out.write(bytes);
    }
}
