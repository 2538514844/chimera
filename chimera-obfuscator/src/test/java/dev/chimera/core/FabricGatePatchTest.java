package dev.chimera.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** G7: fabric.mod.json must keep existing entrypoints and gain a preLaunch hook. */
class FabricGatePatchTest {

    private static final String WURST = """
            {
              "schemaVersion": 1,
              "id": "wurst",
              "entrypoints": {
                "main": ["net.wurstclient.WurstInitializer"]
              },
              "mixins": ["wurst.mixins.json"]
            }
            """;

    @Test
    void addsPreLaunchAndKeepsExistingEntrypoints() {
        String patched = FabricGatePatch.addPreLaunch(WURST);
        assertTrue(patched.contains("\"preLaunch\""));
        assertTrue(patched.contains(FabricGatePatch.PRELAUNCH_ENTRYPOINT));
        assertTrue(patched.contains("net.wurstclient.WurstInitializer"), "main entrypoint kept");
        assertTrue(patched.contains("wurst.mixins.json"), "mixin config kept");
        assertTrue(patched.startsWith("{"));
    }

    @Test
    void isIdempotent() {
        String once = FabricGatePatch.addPreLaunch(WURST);
        String twice = FabricGatePatch.addPreLaunch(once);
        assertEquals(once, twice);
    }

    @Test
    void mergesIntoExistingPreLaunchArray() {
        String withPreLaunch = "{\"id\":\"x\",\"preLaunch\":[\"other.Mod\"]}";
        String patched = FabricGatePatch.addPreLaunch(withPreLaunch);
        assertTrue(patched.contains("\"other.Mod\""), "existing preLaunch entry kept");
        assertTrue(patched.contains(FabricGatePatch.PRELAUNCH_ENTRYPOINT));
    }

    @Test
    void rejectsNonObject() {
        assertTrue(throwsIllegalArgument(() -> FabricGatePatch.addPreLaunch("[]")));
        assertTrue(throwsIllegalArgument(() -> FabricGatePatch.addPreLaunch("")));
    }

    private static boolean throwsIllegalArgument(Runnable action) {
        try {
            action.run();
            return false;
        } catch (IllegalArgumentException expected) {
            return true;
        }
    }
}
