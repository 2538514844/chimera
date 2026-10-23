package dev.chimera.transform.mixinsupport;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Rewrites a refmap ({@code *-refmap.json}) so it no longer leaks the pre-rename names.
 *
 * <p>The tree is walked generically instead of relying on one exact refmap schema. Handled
 * shapes:</p>
 * <ul>
 *   <li>class names in binary ({@code a.b.C}) or internal ({@code a/b/C}) form;</li>
 *   <li>descriptors and member keys such as {@code La/b/C;}, {@code La/b/C;field:Lx/Y;} and
 *       {@code La/b/C;method(Lx/Y;)V};</li>
 *   <li>dotted member references such as {@code a.b.C.member};</li>
 *   <li>plain member names that are values inside a class-keyed object (e.g. the mixin class
 *       section of {@code mappings}/{@code data}), resolved through the owner's member plan.</li>
 * </ul>
 *
 * <p>Deleting the refmap ({@link MixinSupport.Plan#stripRefmap}) is the safer option once names
 * changed, because a refmap always reveals the original target names. Rewriting is offered for
 * pipelines that still need the mapping data.</p>
 */
final class RefmapRewriter {

    record Update(byte[] bytes, boolean changed) {
    }

    private RefmapRewriter() {
    }

    static Update rewrite(String resourceName, byte[] data, Mappings mappings) {
        Object root;
        try {
            root = Json.parse(new String(data, StandardCharsets.UTF_8));
        } catch (Json.ParseException e) {
            throw new MixinSupportException("malformed refmap \"" + resourceName + "\"", e);
        }
        Object rewritten = rewriteValue(root, mappings, null);
        if (rewritten == root) {
            return new Update(data, false);
        }
        return new Update(Json.write(rewritten).getBytes(StandardCharsets.UTF_8), true);
    }

    private static Object rewriteValue(Object node, Mappings mappings, String contextOwner) {
        if (node instanceof String text) {
            String mapped = mapString(text, mappings, contextOwner);
            return mapped.equals(text) ? node : mapped;
        }
        if (node instanceof List<?> list) {
            List<Object> out = new ArrayList<>(list.size());
            boolean changed = false;
            for (Object item : list) {
                Object mapped = rewriteValue(item, mappings, contextOwner);
                changed |= mapped != item;
                out.add(mapped);
            }
            return changed ? out : node;
        }
        if (node instanceof Map<?, ?> map) {
            Map<String, Object> out = new LinkedHashMap<>();
            boolean changed = false;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                String key = String.valueOf(entry.getKey());
                String mappedKey = mapString(key, mappings, contextOwner);
                String childOwner = contextOwner;
                if (isClassKey(key) && entry.getValue() instanceof Map) {
                    childOwner = Mappings.toInternal(key);
                }
                Object value = rewriteValue(entry.getValue(), mappings, childOwner);
                changed |= !mappedKey.equals(key) || value != entry.getValue();
                out.put(mappedKey, value);
            }
            return changed ? out : node;
        }
        return node;
    }

    private static boolean isClassKey(String key) {
        if (key.indexOf(':') >= 0 || key.indexOf(' ') >= 0 || key.indexOf('(') >= 0) {
            return false;
        }
        return key.indexOf('/') >= 0 || key.indexOf('.') >= 0;
    }

    private static String mapString(String text, Mappings mappings, String contextOwner) {
        if (text == null || text.isEmpty()) {
            return text;
        }

        // La/b/C;... member keys and descriptors whose owner is a renamed class.
        if (text.charAt(0) == 'L' && text.indexOf(';') > 1) {
            int end = text.indexOf(';');
            String owner = text.substring(1, end);
            String mappedOwner = mappings.mapInternal(owner);
            String rest = text.substring(end + 1);
            String mappedRest = mapMemberSuffix(rest, owner, mappings);
            if (!mappedOwner.equals(owner) || !mappedRest.equals(rest)) {
                return "L" + mappedOwner + ";" + mappedRest;
            }
        }

        if (text.charAt(0) == '(' || text.charAt(0) == '[') {
            String descriptor = mappings.mapDescriptor(text);
            if (!descriptor.equals(text)) {
                return descriptor;
            }
        }

        String classOnly = mappings.mapClass(text);
        if (!classOnly.equals(text)) {
            return classOnly;
        }

        String qualified = mapQualifiedMember(text, mappings);
        if (qualified != null && !qualified.equals(text)) {
            return qualified;
        }

        if (contextOwner != null && isPlainIdentifier(text)) {
            String member = mappings.mapMember(contextOwner, text, null);
            if (!member.equals(text)) {
                return member;
            }
        }
        return text;
    }

    private static String mapMemberSuffix(String rest, String owner, Mappings mappings) {
        if (rest.isEmpty()) {
            return rest;
        }
        int paren = rest.indexOf('(');
        int colon = rest.indexOf(':');
        int separator;
        if (paren < 0 && colon < 0) {
            if (isPlainIdentifier(rest)) {
                return mappings.mapMember(owner, rest, null);
            }
            return mappings.mapDescriptor(rest);
        }
        separator = paren < 0 ? colon : (colon < 0 ? paren : Math.min(paren, colon));
        String name = rest.substring(0, separator);
        if (!isPlainIdentifier(name)) {
            return mappings.mapDescriptor(rest);
        }
        String descriptor = rest.substring(separator);
        String member = mappings.mapMember(owner, name, descriptor);
        if (member.equals(name) && descriptor.startsWith(":")) {
            member = mappings.mapMember(owner, name, descriptor.substring(1));
        }
        return member + mappings.mapDescriptor(descriptor);
    }

    private static String mapQualifiedMember(String text, Mappings mappings) {
        int dot = text.lastIndexOf('.');
        while (dot > 0) {
            String owner = text.substring(0, dot);
            String internal = Mappings.toInternal(owner);
            String mappedOwner = mappings.mappedInternal(internal);
            if (mappedOwner != null) {
                String member = text.substring(dot + 1);
                if (isPlainIdentifier(member)) {
                    member = mappings.mapMember(internal, member, null);
                }
                return mappedOwner.replace('/', '.') + "." + member;
            }
            dot = text.lastIndexOf('.', dot - 1);
        }
        return null;
    }

    private static boolean isPlainIdentifier(String text) {
        if (text.isEmpty() || text.length() > 512) {
            return false;
        }
        if (!Character.isJavaIdentifierStart(text.charAt(0))) {
            return false;
        }
        for (int i = 1; i < text.length(); i++) {
            if (!Character.isJavaIdentifierPart(text.charAt(i))) {
                return false;
            }
        }
        return true;
    }
}
