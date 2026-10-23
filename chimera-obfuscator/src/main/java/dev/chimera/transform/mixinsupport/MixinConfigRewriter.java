package dev.chimera.transform.mixinsupport;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Rewrites one Sponge Mixin configuration ({@code mixins.json}).
 *
 * <p>Handled fields:</p>
 * <ul>
 *   <li>{@code package}: rewritten only when the rename plan yields one consistent new package
 *       for every mixin referenced by this config. If classes move to different packages (or an
 *       unmapped mixin would be left behind), the field is kept and the affected entries are
 *       emitted fully qualified instead.</li>
 *   <li>{@code mixins}/{@code client}/{@code server}: each class reference is resolved against
 *       the (old) package, mapped through the rename plan and written back relative to the new
 *       package when possible.</li>
 *   <li>{@code refmap}: removed when {@link MixinSupport.Plan#stripRefmap} is set and the
 *       referenced refmap resource exists; the resource itself is deleted by
 *       {@link MixinSupport}.</li>
 * </ul>
 *
 * <p>Unknown fields (priority, compatibilityLevel, plugin, injectors, ...) are preserved as
 * parsed values. The caller must have parsed the document already; malformed JSON is handled
 * fail-closed by {@link MixinSupport} before this class is called.</p>
 */
final class MixinConfigRewriter {

    private static final String[] ARRAY_KEYS = {"mixins", "client", "server"};

    record Update(byte[] bytes, boolean changed, String refmapPath) {
    }

    private MixinConfigRewriter() {
    }

    /**
     * True when a parsed JSON document is a Mixin config rather than, for example,
     * {@code fabric.mod.json} (whose {@code mixins} array lists config file names, not classes).
     * A real config has at least one class array plus a {@code package} string; the file-name
     * fallback keeps configs without a package working.
     */
    static boolean looksLikeMixinConfig(String resourceName, Object root) {
        if (!(root instanceof Map<?, ?> json)) {
            return false;
        }
        boolean hasClassArray = isStringArray(json.get("mixins"))
                || isStringArray(json.get("client"))
                || isStringArray(json.get("server"));
        if (!hasClassArray) {
            return false;
        }
        if (json.get("package") instanceof String) {
            return true;
        }
        return resourceName.toLowerCase(Locale.ROOT).contains("mixin");
    }

    private static boolean isStringArray(Object value) {
        if (!(value instanceof List<?> list)) {
            return false;
        }
        for (Object item : list) {
            if (!(item instanceof String)) {
                return false;
            }
        }
        return true;
    }

    @SuppressWarnings("unchecked")
    static Update rewrite(byte[] original, Map<String, Object> parsed, Mappings mappings,
                          boolean stripRefmap, Set<String> resourceKeys) {
        Map<String, Object> json = new LinkedHashMap<>(parsed);
        boolean changed = false;
        String refmapPath = json.get("refmap") instanceof String value ? value : null;

        String oldPackage = json.get("package") instanceof String value ? value : null;
        if (oldPackage != null && oldPackage.endsWith(".")) {
            oldPackage = oldPackage.substring(0, oldPackage.length() - 1);
        }
        String oldPackageInternal = oldPackage == null ? null : Mappings.toInternal(oldPackage);

        List<EntryRef> entries = new ArrayList<>();
        for (String arrayKey : ARRAY_KEYS) {
            Object value = json.get(arrayKey);
            if (!(value instanceof List<?> list)) {
                continue;
            }
            for (int index = 0; index < list.size(); index++) {
                if (!(list.get(index) instanceof String name)) {
                    continue;
                }
                EntryRef entry = resolve(name, oldPackage, mappings);
                if (entry != null) {
                    entry.arrayKey = arrayKey;
                    entry.index = index;
                    entry.raw = name;
                    entries.add(entry);
                }
            }
        }

        String packageCandidate = null;
        boolean uniform = true;
        boolean anyMapped = false;
        if (oldPackageInternal != null) {
            for (EntryRef entry : entries) {
                if (!entry.mapped) {
                    continue;
                }
                anyMapped = true;
                String candidate = newPackageFor(entry, oldPackageInternal);
                if (candidate == null) {
                    uniform = false;
                    break;
                }
                if (packageCandidate == null) {
                    packageCandidate = candidate;
                } else if (!packageCandidate.equals(candidate)) {
                    uniform = false;
                    break;
                }
            }
        }
        if (!uniform || !anyMapped) {
            packageCandidate = null;
        }
        if (packageCandidate != null && !packageCandidate.equals(oldPackageInternal)) {
            // A mixin that was not renamed still lives in the old package. Rewriting the package
            // would make it unresolvable, so keep the field and fully qualify the moved entries.
            for (EntryRef entry : entries) {
                if (!entry.mapped) {
                    packageCandidate = null;
                    break;
                }
            }
        }
        if (packageCandidate != null && packageCandidate.isEmpty()) {
            packageCandidate = null;
        }

        String effectivePackage = oldPackage;
        if (packageCandidate != null && !packageCandidate.equals(oldPackageInternal)) {
            effectivePackage = packageCandidate.replace('/', '.');
            json.put("package", effectivePackage);
            changed = true;
        }

        String packagePrefix = effectivePackage == null || effectivePackage.isEmpty()
                ? null : effectivePackage + ".";
        for (EntryRef entry : entries) {
            if (!entry.mapped) {
                continue;
            }
            String newFull = entry.newInternal.replace('/', '.');
            String newValue = packagePrefix != null && newFull.startsWith(packagePrefix)
                    ? newFull.substring(packagePrefix.length())
                    : newFull;
            if (!newValue.equals(entry.raw)) {
                ((List<Object>) json.get(entry.arrayKey)).set(entry.index, newValue);
                changed = true;
            }
        }

        if (stripRefmap && refmapPath != null
                && resourceKeys.contains(MixinSupport.normalizeResourcePath(refmapPath))
                && json.remove("refmap") != null) {
            changed = true;
        }

        byte[] bytes = changed ? Json.write(json).getBytes(StandardCharsets.UTF_8) : original;
        return new Update(bytes, changed, refmapPath);
    }

    private static EntryRef resolve(String raw, String oldPackage, Mappings mappings) {
        String value = raw.trim();
        if (value.isEmpty() || value.indexOf(' ') >= 0 || value.indexOf('\t') >= 0) {
            return null;
        }
        String dotted = value.replace('/', '.');
        String absoluteInternal = dotted.replace('.', '/');
        String relativeInternal = oldPackage == null || oldPackage.isEmpty()
                ? absoluteInternal
                : Mappings.toInternal(oldPackage + "." + dotted);
        boolean absoluteKnown = mappings.knowsClass(absoluteInternal);
        boolean relativeKnown = mappings.knowsClass(relativeInternal);
        String oldInternal;
        if (oldPackage != null && !oldPackage.isEmpty()
                && (dotted.equals(oldPackage) || dotted.startsWith(oldPackage + "."))) {
            // Already qualified with this config's package (e.g. "com.example.mixin.MyMixin").
            oldInternal = absoluteInternal;
        } else if (absoluteKnown && !relativeKnown) {
            // Fully qualified entry outside the package (accepted by some mods): trust the plan.
            oldInternal = absoluteInternal;
        } else if (relativeKnown && !absoluteKnown) {
            oldInternal = relativeInternal;
        } else {
            // Standard Mixin semantics: entries are relative to "package".
            oldInternal = relativeInternal;
        }
        String newInternal = mappings.mapInternal(oldInternal);
        return new EntryRef(oldInternal, newInternal);
    }

    private static String newPackageFor(EntryRef entry, String oldPackageInternal) {
        String oldName = packageOf(entry.oldInternal);
        String newName = packageOf(entry.newInternal);
        if (oldName.equals(oldPackageInternal)) {
            return newName;
        }
        if (oldName.startsWith(oldPackageInternal + "/")) {
            String subPackage = oldName.substring(oldPackageInternal.length());
            if (newName.endsWith(subPackage)) {
                return newName.substring(0, newName.length() - subPackage.length());
            }
            return null;
        }
        // A fully qualified entry outside the config package cannot drive a package rename.
        return null;
    }

    private static String packageOf(String internalName) {
        int slash = internalName.lastIndexOf('/');
        return slash < 0 ? "" : internalName.substring(0, slash);
    }

    private static final class EntryRef {

        final String oldInternal;
        final String newInternal;
        final boolean mapped;
        String arrayKey;
        int index;
        String raw;

        EntryRef(String oldInternal, String newInternal) {
            this.oldInternal = oldInternal;
            this.newInternal = newInternal;
            this.mapped = !oldInternal.equals(newInternal);
        }
    }
}
