package dev.chimera.transform.mixin;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import dev.chimera.core.ModProfile;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * S3': keeps @Mixin classes fully encrypted by attaching the decrypting agent before Mixin reads
 * them.
 *
 * <p>Boot order (verified against sponge-mixin 0.17.3 / mixin 0.8.7 bytecode and on a real client):
 * {@code MixinProcessor.checkSelect -> select -> selectConfigs -> MixinConfig.onSelect} instantiates
 * every config plugin, and only afterwards {@code prepareConfigs -> MixinConfig.prepare ->
 * prepareMixins -> MixinInfo.loadMixinClass -> IMixinService.getClassBytes} reads mixin class bytes.
 * A plugin therefore runs early enough; {@code preLaunch} entrypoints do not (their own class load
 * already triggers the mixin prepare).</p>
 *
 * <p>For every mixin config in the artifact a generated plugin class is injected. It implements
 * {@code IMixinConfigPlugin}, boots the agent in {@code <clinit>} and forwards every call to the
 * config's original plugin (if any) through {@code ChimeraMixinDelegate}.</p>
 */
public final class MixinPluginBootstrap {

    /** Runtime helper that owns the attach + delegate logic (shipped plaintext). */
    public static final String DELEGATE_INTERNAL = "dev/chimera/runtime/ChimeraMixinDelegate";
    /** Generated plugin class name prefix; one class per mixin config. */
    public static final String PLUGIN_INTERNAL_PREFIX = "dev/chimera/runtime/ChimeraMixinPlugin";
    public static final String PLUGIN_BINARY_PREFIX = "dev.chimera.runtime.ChimeraMixinPlugin";

    private static final String PLUGIN_INTERFACE =
            "org/spongepowered/asm/mixin/extensibility/IMixinConfigPlugin";
    private static final String CLASS_NODE = "org/objectweb/asm/tree/ClassNode";
    private static final String MIXIN_INFO = "org/spongepowered/asm/mixin/extensibility/IMixinInfo";

    /** Outcome of the artifact pass. */
    public record Result(Map<String, byte[]> generated, List<String> patchedConfigs,
                         Set<String> originalPlugins) {
    }

    private MixinPluginBootstrap() {
    }

    /**
     * Injects the plugin bootstrap for every mixin config found in {@code resources}; the JSON
     * resources are rewritten in place. Returns the generated classes plus the classes that must
     * stay plaintext and keep their names (the mods' own plugin classes).
     */
    public static Result apply(Map<String, byte[]> resources) {
        List<String> configs = new ArrayList<>();
        for (Map.Entry<String, byte[]> entry : resources.entrySet()) {
            String name = entry.getKey();
            if (!name.endsWith(".json") || "fabric.mod.json".equals(name)) {
                continue;
            }
            if (isMixinConfig(new String(entry.getValue(), StandardCharsets.UTF_8))) {
                configs.add(name);
            }
        }
        Collections.sort(configs);

        Map<String, byte[]> generated = new LinkedHashMap<>();
        List<String> patched = new ArrayList<>();
        Set<String> originalPlugins = new TreeSet<>();
        int index = 0;
        for (String config : configs) {
            String text = new String(resources.get(config), StandardCharsets.UTF_8);
            String original = ModProfile.MatcherFinder.firstString(text, "plugin");
            String delegate = original == null ? "" : original.trim().replace('/', '.');
            if (delegate.startsWith(PLUGIN_BINARY_PREFIX)) {
                // A5/idempotency: re-protecting an already protected artifact must not make the
                // injected plugin delegate to itself (that would recurse on every mixin hook).
                delegate = "";
            }
            if (!delegate.isEmpty()) {
                originalPlugins.add(delegate.replace('.', '/'));
            }
            String internal = PLUGIN_INTERNAL_PREFIX + index;
            String binary = PLUGIN_BINARY_PREFIX + index;
            generated.put(internal + ".class", generatePlugin(delegate, index));
            resources.put(config, patchPlugin(text, binary).getBytes(StandardCharsets.UTF_8));
            patched.add(config);
            index++;
        }
        return new Result(generated, patched, originalPlugins);
    }

    /** A mixin config always declares a package plus at least one mixin list. */
    static boolean isMixinConfig(String text) {
        if (!text.contains("\"package\"")) {
            return false;
        }
        return text.contains("\"mixins\"") || text.contains("\"client\"")
                || text.contains("\"server\"");
    }

    /** Replaces or inserts the {@code plugin} key without reformatting the rest of the file. */
    static String patchPlugin(String json, String binaryName) {
        java.util.regex.Pattern existing = java.util.regex.Pattern
                .compile("\"plugin\"\\s*:\\s*\"[^\"]*\"");
        java.util.regex.Matcher matcher = existing.matcher(json);
        if (matcher.find()) {
            return matcher.replaceFirst(java.util.regex.Matcher.quoteReplacement(
                    "\"plugin\": \"" + binaryName + "\""));
        }
        int brace = json.indexOf('{');
        if (brace < 0) {
            return json;
        }
        String remainder = json.substring(brace + 1);
        String trimmed = remainder.replaceFirst("^\\s*", "");
        String separator = trimmed.isEmpty() ? "" : ",\n  ";
        return json.substring(0, brace + 1) + "\n  \"plugin\": \"" + binaryName + "\""
                + separator + trimmed;
    }

    /** Generates the thin {@code IMixinConfigPlugin} shell for one config. */
    static byte[] generatePlugin(String delegateBinaryName, int index) {
        String internal = PLUGIN_INTERNAL_PREFIX + index;
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER,
                internal, null, "java/lang/Object", new String[]{PLUGIN_INTERFACE});

        MethodVisitor init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(0, 0);
        init.visitEnd();

        // <clinit>: attach the decrypting agent as early as a mod is allowed to run.
        MethodVisitor clinit = writer.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.visitCode();
        clinit.visitMethodInsn(Opcodes.INVOKESTATIC, DELEGATE_INTERNAL, "boot", "()V", false);
        clinit.visitInsn(Opcodes.RETURN);
        clinit.visitMaxs(0, 0);
        clinit.visitEnd();

        MethodVisitor onLoad = writer.visitMethod(Opcodes.ACC_PUBLIC, "onLoad",
                "(Ljava/lang/String;)V", null, null);
        onLoad.visitCode();
        onLoad.visitVarInsn(Opcodes.ALOAD, 1);
        onLoad.visitLdcInsn(delegateBinaryName);
        onLoad.visitMethodInsn(Opcodes.INVOKESTATIC, DELEGATE_INTERNAL, "onLoad",
                "(Ljava/lang/String;Ljava/lang/String;)V", false);
        onLoad.visitInsn(Opcodes.RETURN);
        onLoad.visitMaxs(0, 0);
        onLoad.visitEnd();

        MethodVisitor refMap = writer.visitMethod(Opcodes.ACC_PUBLIC, "getRefMapperConfig",
                "()Ljava/lang/String;", null, null);
        refMap.visitCode();
        refMap.visitLdcInsn(delegateBinaryName);
        refMap.visitMethodInsn(Opcodes.INVOKESTATIC, DELEGATE_INTERNAL, "getRefMapperConfig",
                "(Ljava/lang/String;)Ljava/lang/String;", false);
        refMap.visitInsn(Opcodes.ARETURN);
        refMap.visitMaxs(0, 0);
        refMap.visitEnd();

        MethodVisitor should = writer.visitMethod(Opcodes.ACC_PUBLIC, "shouldApplyMixin",
                "(Ljava/lang/String;Ljava/lang/String;)Z", null, null);
        should.visitCode();
        should.visitVarInsn(Opcodes.ALOAD, 1);
        should.visitVarInsn(Opcodes.ALOAD, 2);
        should.visitLdcInsn(delegateBinaryName);
        should.visitMethodInsn(Opcodes.INVOKESTATIC, DELEGATE_INTERNAL, "shouldApplyMixin",
                "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z", false);
        should.visitInsn(Opcodes.IRETURN);
        should.visitMaxs(0, 0);
        should.visitEnd();

        MethodVisitor accept = writer.visitMethod(Opcodes.ACC_PUBLIC, "acceptTargets",
                "(Ljava/util/Set;Ljava/util/Set;)V", null, null);
        accept.visitCode();
        accept.visitVarInsn(Opcodes.ALOAD, 1);
        accept.visitVarInsn(Opcodes.ALOAD, 2);
        accept.visitLdcInsn(delegateBinaryName);
        accept.visitMethodInsn(Opcodes.INVOKESTATIC, DELEGATE_INTERNAL, "acceptTargets",
                "(Ljava/util/Set;Ljava/util/Set;Ljava/lang/String;)V", false);
        accept.visitInsn(Opcodes.RETURN);
        accept.visitMaxs(0, 0);
        accept.visitEnd();

        MethodVisitor mixins = writer.visitMethod(Opcodes.ACC_PUBLIC, "getMixins",
                "()Ljava/util/List;", null, null);
        mixins.visitCode();
        mixins.visitLdcInsn(delegateBinaryName);
        mixins.visitMethodInsn(Opcodes.INVOKESTATIC, DELEGATE_INTERNAL, "getMixins",
                "(Ljava/lang/String;)Ljava/util/List;", false);
        mixins.visitInsn(Opcodes.ARETURN);
        mixins.visitMaxs(0, 0);
        mixins.visitEnd();

        applyHook(writer, "preApply", delegateBinaryName);
        applyHook(writer, "postApply", delegateBinaryName);

        writer.visitEnd();
        return writer.toByteArray();
    }

    private static void applyHook(ClassWriter writer, String name, String delegateBinaryName) {
        String descriptor = "(Ljava/lang/String;L" + CLASS_NODE + ";Ljava/lang/String;L"
                + MIXIN_INFO + ";)V";
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC, name, descriptor, null, null);
        method.visitCode();
        method.visitVarInsn(Opcodes.ALOAD, 1);
        method.visitVarInsn(Opcodes.ALOAD, 2);
        method.visitVarInsn(Opcodes.ALOAD, 3);
        method.visitVarInsn(Opcodes.ALOAD, 4);
        method.visitLdcInsn(delegateBinaryName);
        method.visitMethodInsn(Opcodes.INVOKESTATIC, DELEGATE_INTERNAL, name,
                "(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;"
                        + "Ljava/lang/String;)V", false);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(0, 0);
        method.visitEnd();
    }
}
