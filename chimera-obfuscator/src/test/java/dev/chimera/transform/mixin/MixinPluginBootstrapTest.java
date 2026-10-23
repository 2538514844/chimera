package dev.chimera.transform.mixin;

import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A3: S3' mixin-plugin bootstrap. Covers the three properties the artifact depends on: one plugin
 * per mixin config, an auto-downgrade signal when there is nothing to patch, and valid bytecode that
 * routes every mixin hook through the Chimera delegate (including re-protection).
 */
class MixinPluginBootstrapTest {

    private static Map<String, byte[]> resources(String... nameAndBody) {
        Map<String, byte[]> map = new LinkedHashMap<>();
        for (int i = 0; i < nameAndBody.length; i += 2) {
            map.put(nameAndBody[i], nameAndBody[i + 1].getBytes(StandardCharsets.UTF_8));
        }
        map.put("fabric.mod.json", "{\"schemaVersion\":1,\"id\":\"t\"}".getBytes(StandardCharsets.UTF_8));
        return map;
    }

    @Test
    void noMixinConfigYieldsNoPatchSoTheCallerCanDowngrade() {
        MixinPluginBootstrap.Result result =
                MixinPluginBootstrap.apply(resources("data/tags.json", "{\"values\":[]}"));
        assertTrue(result.patchedConfigs().isEmpty(), "nothing to patch");
        assertTrue(result.generated().isEmpty(), "no plugin class generated");
        assertTrue(result.originalPlugins().isEmpty());
    }

    @Test
    void patchesEveryConfigAndGeneratesOnePluginPerConfig() {
        MixinPluginBootstrap.Result result = MixinPluginBootstrap.apply(resources(
                "mod.mixins.json", "{\"package\":\"a.mixin\",\"mixins\":[\"A\"]}",
                "mod.client.mixins.json", "{\"package\":\"a.mixin\",\"client\":[\"B\"],"
                        + "\"plugin\":\"a.Plugin\"}"));
        assertEquals(2, result.patchedConfigs().size(), "both configs patched: " + result.patchedConfigs());
        assertEquals(2, result.generated().size(), "one plugin class per config");
        assertEquals(1, result.originalPlugins().size(), "only the config that declared a plugin keeps one");
        assertTrue(result.originalPlugins().contains("a/Plugin"));
        assertTrue(result.generated().containsKey(MixinPluginBootstrap.PLUGIN_INTERNAL_PREFIX + "0.class"));
        assertTrue(result.generated().containsKey(MixinPluginBootstrap.PLUGIN_INTERNAL_PREFIX + "1.class"));
    }

    @Test
    void generatedPluginIsValidBytecodeThatImplementsTheMixinInterface() {
        MixinPluginBootstrap.Result result = MixinPluginBootstrap.apply(resources(
                "mod.mixins.json", "{\"package\":\"a.mixin\",\"mixins\":[\"A\"]}"));
        byte[] bytes = result.generated().get(MixinPluginBootstrap.PLUGIN_INTERNAL_PREFIX + "0.class");
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        assertEquals(MixinPluginBootstrap.PLUGIN_INTERNAL_PREFIX + "0", node.name);
        assertEquals("java/lang/Object", node.superName);
        assertTrue(node.interfaces.contains(
                        "org/spongepowered/asm/mixin/extensibility/IMixinConfigPlugin"),
                "must implement IMixinConfigPlugin: " + node.interfaces);
        assertTrue(node.methods.stream().anyMatch(m -> "<clinit>".equals(m.name)),
                "bootstrap must run from <clinit> (earlier than any mixin byte read)");
        // IMixinConfigPlugin's onSelect/preApply/postApply are interface defaults; the injected
        // class overrides exactly the hooks the artifact needs to forward to the delegate.
        for (String hook : new String[]{"onLoad", "getMixins", "getRefMapperConfig",
                "shouldApplyMixin", "acceptTargets"}) {
            MethodNode method = node.methods.stream().filter(m -> hook.equals(m.name))
                    .findFirst().orElse(null);
            assertTrue(method != null, "plugin must implement " + hook);
            assertTrue(method.instructions.size() > 0, hook + " must forward to the delegate");
        }
    }

    @Test
    void reProtectingAnAlreadyProtectedArtifactDoesNotSelfDelegate() {
        Map<String, byte[]> once = resources(
                "mod.mixins.json", "{\"package\":\"a.mixin\",\"mixins\":[\"A\"]}");
        MixinPluginBootstrap.apply(once);
        MixinPluginBootstrap.Result twice = MixinPluginBootstrap.apply(once);
        assertEquals(1, twice.patchedConfigs().size());
        assertTrue(twice.originalPlugins().isEmpty(),
                "the injected plugin must not be recorded as the mod's own plugin: "
                        + twice.originalPlugins());
        String patched = new String(once.get("mod.mixins.json"), StandardCharsets.UTF_8);
        assertEquals(1, count(patched, "\"plugin\""), "exactly one plugin key: " + patched);
    }

    private static int count(String text, String needle) {
        int found = 0;
        int at = text.indexOf(needle);
        while (at >= 0) {
            found++;
            at = text.indexOf(needle, at + needle.length());
        }
        return found;
    }
}
