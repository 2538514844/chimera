package dev.chimera.core;

/**
 * G7: patches {@code fabric.mod.json} with the Chimera {@code preLaunch} entrypoint so the
 * activation gate runs before Minecraft loads. Fabric reads entrypoints from the
 * {@code entrypoints} object, so the hook is added there; existing entrypoints are preserved.
 */
public final class FabricGatePatch {

    public static final String PRELAUNCH_ENTRYPOINT =
            PreLaunchEntrypointGenerator.BINARY_NAME;

    private FabricGatePatch() {
    }

    /** @return patched JSON (idempotent); input must be a JSON object document */
    public static String addPreLaunch(String json) {
        return addPreLaunchEntry(json, PRELAUNCH_ENTRYPOINT);
    }

    /** Adds an arbitrary {@code preLaunch} entry class (S2 attach bootstrap uses this). */
    public static String addPreLaunchEntry(String json, String binaryName) {
        return insertPreLaunchEntry(json, binaryName, false);
    }

    /**
     * Appends a {@code preLaunch} entry after every existing one.
     *
     * <p>P1-1: the class-encryption attach agent derives its key from the native SessionHandle, so
     * it must run after the licence gate rather than before it. Fabric runs preLaunch entrypoints
     * in array order, so appending is the ordering contract.</p>
     */
    public static String addPreLaunchEntryLast(String json, String binaryName) {
        return insertPreLaunchEntry(json, binaryName, true);
    }

    private static String insertPreLaunchEntry(String json, String binaryName, boolean append) {
        if (json == null || json.isBlank()) {
            throw new IllegalArgumentException("fabric.mod.json is empty");
        }
        int objectStart = json.indexOf('{');
        if (objectStart < 0) {
            throw new IllegalArgumentException("fabric.mod.json is not an object");
        }
        String quoted = '"' + binaryName + '"';
        if (json.contains(quoted)) {
            return json;
        }
        int entrypoints = json.indexOf("\"entrypoints\"");
        if (entrypoints < 0) {
            String entry = "\"entrypoints\": {\"preLaunch\": [" + quoted + "]},";
            int insertAt = objectStart + 1;
            return json.substring(0, insertAt) + entry + json.substring(insertAt);
        }
        int objectBrace = json.indexOf('{', entrypoints);
        if (objectBrace < 0) {
            throw new IllegalArgumentException("entrypoints is not an object");
        }
        int preLaunch = json.indexOf("\"preLaunch\"", objectBrace);
        int closing = findMatchingBrace(json, objectBrace);
        if (closing < 0) {
            throw new IllegalArgumentException("entrypoints object is not closed");
        }
        if (preLaunch >= 0 && preLaunch < closing) {
            int arrayStart = json.indexOf('[', preLaunch);
            if (arrayStart < 0 || arrayStart > closing) {
                throw new IllegalArgumentException("preLaunch is not an array");
            }
            if (append) {
                int arrayEnd = json.indexOf(']', arrayStart);
                if (arrayEnd < 0 || arrayEnd > closing) {
                    throw new IllegalArgumentException("preLaunch array is not closed");
                }
                boolean empty = json.substring(arrayStart + 1, arrayEnd).isBlank();
                return json.substring(0, arrayEnd) + (empty ? quoted : "," + quoted)
                        + json.substring(arrayEnd);
            }
            return json.substring(0, arrayStart + 1) + quoted + ',' + json.substring(arrayStart + 1);
        }
        int insertAt = objectBrace + 1;
        String entry = "\"preLaunch\": [" + quoted + "],";
        return json.substring(0, insertAt) + entry + json.substring(insertAt);
    }

    /** Prepends the generated main entrypoint so post-bootstrap init runs before mods. */
    public static String addMain(String json) {
        if (json == null || json.isBlank()) {
            throw new IllegalArgumentException("fabric.mod.json is empty");
        }
        int objectStart = json.indexOf('{');
        if (objectStart < 0) {
            throw new IllegalArgumentException("fabric.mod.json is not an object");
        }
        String quoted = '"' + MainEntrypointGenerator.BINARY_NAME + '"';
        if (json.contains(quoted)) {
            return json;
        }
        int entrypoints = json.indexOf("\"entrypoints\"");
        if (entrypoints < 0) {
            String entry = "\"entrypoints\": {\"main\": [" + quoted + "]},";
            int insertAt = objectStart + 1;
            return json.substring(0, insertAt) + entry + json.substring(insertAt);
        }
        int objectBrace = json.indexOf('{', entrypoints);
        if (objectBrace < 0) {
            throw new IllegalArgumentException("entrypoints is not an object");
        }
        int closing = findMatchingBrace(json, objectBrace);
        if (closing < 0) {
            throw new IllegalArgumentException("entrypoints object is not closed");
        }
        int mainKey = json.indexOf("\"main\"", objectBrace);
        if (mainKey >= 0 && mainKey < closing) {
            int arrayStart = json.indexOf('[', mainKey);
            if (arrayStart < 0 || arrayStart > closing) {
                throw new IllegalArgumentException("main is not an array");
            }
            return json.substring(0, arrayStart + 1) + quoted + ',' + json.substring(arrayStart + 1);
        }
        int insertAt = objectBrace + 1;
        String entry = "\"main\": [" + quoted + "],";
        return json.substring(0, insertAt) + entry + json.substring(insertAt);
    }

    private static int findMatchingBrace(String json, int open) {
        int depth = 0;
        boolean inString = false;
        for (int i = open; i < json.length(); i++) {
            char c = json.charAt(i);
            if (inString) {
                if (c == '\\') {
                    i++;
                } else if (c == '"') {
                    inString = false;
                }
                continue;
            }
            if (c == '"') {
                inString = true;
            } else if (c == '{') {
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0) {
                    return i;
                }
            }
        }
        return -1;
    }
}
