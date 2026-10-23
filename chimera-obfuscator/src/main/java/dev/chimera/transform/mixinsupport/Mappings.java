package dev.chimera.transform.mixinsupport;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Normalised view of {@link MixinSupport.Plan}: every class/owner name is converted to the
 * internal (slash separated) form so callers may pass either {@code a/b/C} or {@code a.b.C}.
 * Excludes use the same prefix semantics as {@code ChimeraConfig.excludes}: an entry matches the
 * class itself and every class below it ({@code a/b} excludes {@code a/b} and {@code a/b/C}).
 */
final class Mappings {

    private final Map<String, String> classRenames = new LinkedHashMap<>();
    private final Map<String, Map<String, String>> memberRenames = new LinkedHashMap<>();
    private final List<String> excludes = new ArrayList<>();

    Mappings(MixinSupport.Plan plan) {
        for (Map.Entry<String, String> entry : plan.classRenames.entrySet()) {
            String from = toInternal(entry.getKey());
            String to = toInternal(entry.getValue());
            if (from.isEmpty() || to.isEmpty() || from.equals(to)) {
                continue;
            }
            classRenames.put(from, to);
        }
        for (Map.Entry<String, Map<String, String>> entry : plan.memberRenames.entrySet()) {
            String owner = toInternal(entry.getKey());
            if (owner.isEmpty() || entry.getValue() == null) {
                continue;
            }
            Map<String, String> members = new TreeMap<>();
            for (Map.Entry<String, String> member : entry.getValue().entrySet()) {
                String key = member.getKey();
                String value = member.getValue();
                if (key == null || key.isEmpty() || value == null || value.isEmpty()
                        || key.equals(value)) {
                    continue;
                }
                members.put(key, value);
            }
            if (!members.isEmpty()) {
                memberRenames.put(owner, members);
            }
        }
        for (String exclude : plan.excludes) {
            if (exclude == null || exclude.isEmpty()) {
                continue;
            }
            String normalized = toInternal(exclude.trim());
            while (normalized.endsWith("/")) {
                normalized = normalized.substring(0, normalized.length() - 1);
            }
            if (!normalized.isEmpty()) {
                excludes.add(normalized);
            }
        }
    }

    static String toInternal(String name) {
        if (name == null) {
            return "";
        }
        return name.replace('\\', '/').replace('.', '/');
    }

    boolean isEmpty() {
        return classRenames.isEmpty() && memberRenames.isEmpty();
    }

    /** True when the plan names this class either as a rename source or as a member owner. */
    boolean knowsClass(String internalName) {
        return internalName != null
                && (classRenames.containsKey(internalName) || memberRenames.containsKey(internalName));
    }

    boolean isExcluded(String internalName) {
        if (internalName == null) {
            return false;
        }
        for (String exclude : excludes) {
            if (internalName.equals(exclude) || internalName.startsWith(exclude + "/")) {
                return true;
            }
        }
        return false;
    }

    /** Maps an internal class name, or returns it unchanged when not renamed/excluded. */
    String mapInternal(String internalName) {
        String mapped = mappedInternal(internalName);
        return mapped == null ? internalName : mapped;
    }

    /** @return the mapped internal name, or {@code null} when the class is not renamed/excluded. */
    String mappedInternal(String internalName) {
        if (internalName == null || internalName.isEmpty() || isExcluded(internalName)) {
            return null;
        }
        return classRenames.get(internalName);
    }

    /**
     * Maps a class name that appears in metadata, preserving the separator style of the input
     * ({@code a.b.C} stays binary, {@code a/b/C} stays internal).
     */
    String mapClass(String name) {
        if (name == null || name.isEmpty()) {
            return name;
        }
        boolean binary = name.indexOf('/') < 0 && name.indexOf('.') >= 0;
        String internal = binary ? name.replace('.', '/') : name;
        String mapped = mappedInternal(internal);
        if (mapped == null) {
            return name;
        }
        return binary ? mapped.replace('/', '.') : mapped;
    }

    /**
     * Maps one member of {@code ownerInternal}.
     *
     * @param descriptor optional descriptor (ASM syntax, e.g. {@code ()V} or {@code I}); used for
     *                   an exact {@code name + descriptor} lookup before falling back to a
     *                   descriptor-less lookup when it is unambiguous
     */
    String mapMember(String ownerInternal, String name, String descriptor) {
        if (ownerInternal == null || name == null || name.isEmpty()
                || isExcluded(ownerInternal)) {
            return name;
        }
        Map<String, String> members = memberRenames.get(ownerInternal);
        if (members == null) {
            return name;
        }
        if (descriptor != null) {
            String direct = members.get(name + descriptor);
            if (direct == null && !descriptor.startsWith(":") && !descriptor.startsWith("(")) {
                // Plan keys may use a field descriptor with or without the refmap's ':'.
                direct = members.get(name + ":" + descriptor);
            }
            if (direct != null) {
                return direct;
            }
        }
        String bare = members.get(name);
        if (bare != null) {
            return bare;
        }
        String unique = null;
        for (Map.Entry<String, String> entry : members.entrySet()) {
            String key = entry.getKey();
            if (!key.startsWith(name) || key.length() == name.length()) {
                continue;
            }
            String suffix = key.substring(name.length());
            if (suffix.startsWith(":")) {
                // Refmap keys use "name:descriptor" for fields; the plan uses "name+descriptor".
                suffix = suffix.substring(1);
            }
            if (!isDescriptorSuffix(suffix)) {
                continue;
            }
            if (unique == null) {
                unique = entry.getValue();
            } else if (!unique.equals(entry.getValue())) {
                return name;
            }
        }
        return unique == null ? name : unique;
    }

    /**
     * Rewrites every {@code Lpkg/Type;} token of an ASM type/method descriptor. Used for refmap
     * keys and for {@code @Mixin(value = SomeClass[].class)} style annotation values.
     */
    String mapDescriptor(String descriptor) {
        if (descriptor == null || descriptor.isEmpty()) {
            return descriptor;
        }
        StringBuilder out = new StringBuilder(descriptor.length() + 16);
        boolean changed = false;
        int index = 0;
        while (index < descriptor.length()) {
            char c = descriptor.charAt(index);
            if (c == 'L') {
                int semicolon = descriptor.indexOf(';', index + 1);
                if (semicolon > index + 1) {
                    String internal = descriptor.substring(index + 1, semicolon);
                    String mapped = mapInternal(internal);
                    if (!mapped.equals(internal)) {
                        changed = true;
                    }
                    out.append('L').append(mapped).append(';');
                    index = semicolon + 1;
                    continue;
                }
            }
            out.append(c);
            index++;
        }
        return changed ? out.toString() : descriptor;
    }

    private static boolean isDescriptorSuffix(String suffix) {
        if (suffix.isEmpty()) {
            return false;
        }
        if (suffix.charAt(0) == '(') {
            return true;
        }
        int[] position = {0};
        return parseFieldType(suffix, position) && position[0] == suffix.length();
    }

    private static boolean parseFieldType(String text, int[] position) {
        int index = position[0];
        if (index >= text.length()) {
            return false;
        }
        char c = text.charAt(index);
        if ("ZBCSIJFD".indexOf(c) >= 0) {
            position[0] = index + 1;
            return true;
        }
        if (c == '[') {
            position[0] = index + 1;
            return parseFieldType(text, position);
        }
        if (c == 'L') {
            int semicolon = text.indexOf(';', index + 1);
            if (semicolon < 0) {
                return false;
            }
            position[0] = semicolon + 1;
            return true;
        }
        return false;
    }
}
