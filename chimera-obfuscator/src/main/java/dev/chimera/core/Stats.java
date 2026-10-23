package dev.chimera.core;

public final class Stats {
    public int classesRead;
    public int classesWritten;
    public int stringsEncrypted;
    public int methodsFragmented;
    public int methodsNativeStubbed;
    public int entangledMethods;
    public int honeypotInjected;
    public int vmMethods;
    public int renamedClasses;
    public int renamedMethods;
    public int pregameInjections;
    public int hardenedClasses;
    public int hardenedSignatures;
    public int hardenedFakeRefs;
    public int hardenedDummyMethods;
    public int hardenedConstants;
    public int hardenedDecoys;
    public int invisibleClassesRenamed;
    public int invisibleMethodsRenamed;
    public int invisibleFieldsRenamed;
    public int invisibleStringsSynced;
    public int invisibleResourcesSynced;
    public int invisibleProtectedClasses;
    public int invisibleProtectedMembers;
    public int indyClasses;
    public int indyInvokeSites;
    public int indyRewritten;
    public int indySkipped;
    public int indyMemberEntries;
    public int indyMemberTableBytes;
    public int indyPreservedMixinClasses;
    /** M10 skip-reason distribution (label -> count) for the build log. */
    public java.util.Map<String, Integer> indySkipReasons = new java.util.LinkedHashMap<>();
    public int cfgMethodsFlattened;
    public int cfgMethodsPredicated;
    public int cfgConstantChains;
    public int cfgSkippedMixin;
    public int cfgSkippedTryCatch;
    public int cfgSkippedUnsafe;
    public int debugClassesStripped;
    public int debugLineNumbersRemoved;
    public int debugLocalVarsRemoved;
    public int debugClassesSkipped;
    public int shuffledClasses;
    public int shuffledFields;
    public int shuffledMethods;
    public int fieldInitSunk;
    public int invokeWrapped;
    public int bsmVariants;
    public int wmShardsWritten;
    public int wmClassesCarried;
    public int payloadOverlaysWritten;
    public int payloadOverlayBytes;
    /** #24 payload-stealth: size of the CHS1 blob embedded as the disguised resource. */
    public int payloadStealthBytes;
    public int mixinJsonRewritten;
    public int mixinRefmapRemoved;
    public int mixinTargetsMapped;
    public int hiddenClassEntries;
    public int encryptedClasses;
    public int nativeSinkSelected;
    /** B1: distinct classes the native sink actually removed bodies from. */
    public int nativeSinkClasses;
    /** B1: sum of the selected methods' call weights (core-logic share). */
    public long nativeSinkWeight;
    public int chunksWritten;
    public long elapsedMs;

    /** I1: flat JSON object of every public counter (consumed by {@code --stats-json}). */
    public String toJson() {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (java.lang.reflect.Field field : Stats.class.getFields()) {
            int mod = field.getModifiers();
            if (!java.lang.reflect.Modifier.isPublic(mod)
                    || java.lang.reflect.Modifier.isStatic(mod)) {
                continue;
            }
            try {
                Object value = field.get(this);
                if (!first) {
                    sb.append(',');
                }
                first = false;
                sb.append('"').append(field.getName()).append("\":");
                if (value instanceof java.util.Map<?, ?> map) {
                    sb.append('{');
                    boolean innerFirst = true;
                    for (java.util.Map.Entry<?, ?> entry : map.entrySet()) {
                        if (!innerFirst) {
                            sb.append(',');
                        }
                        innerFirst = false;
                        sb.append('"').append(entry.getKey()).append("\":").append(entry.getValue());
                    }
                    sb.append('}');
                } else if (value instanceof Number number) {
                    sb.append(number);
                } else if (value instanceof Boolean flag) {
                    sb.append(flag);
                } else {
                    sb.append('"').append(String.valueOf(value)
                            .replace("\\", "\\\\").replace("\"", "\\\"")).append('"');
                }
            } catch (IllegalAccessException ignored) {
                // public fields only; unreachable
            }
        }
        return sb.append('}').toString();
    }

    @Override
    public String toString() {
        return "classes=" + classesRead + "->" + classesWritten
                + ", strings=" + stringsEncrypted
                + ", fragments=" + methodsFragmented
                + ", native=" + methodsNativeStubbed
                + ", entangled=" + entangledMethods
                + ", honeypot=" + honeypotInjected
                + ", vm=" + vmMethods
                + ", renamedClasses=" + renamedClasses
                + ", renamedMethods=" + renamedMethods
                + ", pregame=" + pregameInjections
                + ", hardenClasses=" + hardenedClasses
                + ", hardenSignatures=" + hardenedSignatures
                + ", hardenDummies=" + hardenedDummyMethods
                + ", hardenDecoys=" + hardenedDecoys
                + ", invisible=" + invisibleClassesRenamed + "c/"
                + (invisibleMethodsRenamed + invisibleFieldsRenamed) + "m"
                + ", invisibleSync=" + invisibleStringsSynced + "s/"
                + invisibleResourcesSynced + "r"
                + ", invisibleProtected=" + invisibleProtectedClasses + "c/"
                + invisibleProtectedMembers + "m"
                + ", indy=" + indyRewritten + "/" + indyInvokeSites + " (" + indyClasses + "c)"
                + ", indyTable=" + indyMemberEntries + "e/" + indyMemberTableBytes + "B"
                + (indySkipReasons.isEmpty() ? "" : ", indySkip=" + indySkipReasons)
                + ", cfg=" + cfgMethodsFlattened + "flat/" + cfgMethodsPredicated + "pred/"
                + cfgConstantChains + "chain"
                + ", cfgSkip=" + cfgSkippedMixin + "m/" + cfgSkippedTryCatch + "t/"
                + cfgSkippedUnsafe + "u"
                + ", debug=" + debugClassesStripped + "c/" + debugLineNumbersRemoved + "ln/"
                + debugLocalVarsRemoved + "lv"
                + ", shuffle=" + shuffledClasses + "c/" + shuffledFields + "f/" + shuffledMethods + "m"
                + ", wm=" + wmShardsWritten + "s/" + wmClassesCarried + "c"
                + ", overlay=" + payloadOverlaysWritten + "/" + payloadOverlayBytes + "B"
                + (payloadStealthBytes > 0 ? ", stealth=" + payloadStealthBytes + "B" : "")
                + (nativeSinkSelected > 0
                        ? ", sink=" + nativeSinkSelected + "m/" + nativeSinkClasses + "c"
                        : "")
                + ", chunks=" + chunksWritten
                + ", elapsedMs=" + elapsedMs;
    }
}
