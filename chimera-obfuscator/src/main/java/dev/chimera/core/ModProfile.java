package dev.chimera.core;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Per-mod build profile derived purely from the input jar. The engine uses it to decide which
 * classes Fabric/JVM must be able to resolve by name before preLaunch (and therefore cannot be
 * hidden) without any mod-specific code.
 */
public final class ModProfile {

    public final String inputJar;
    public final Set<String> entrypoints = new TreeSet<>();
    public final Set<String> mixinClasses = new TreeSet<>();
    /** Original {@code plugin} classes declared by the mixin configs (loadable, never encrypted). */
    public final Set<String> mixinPlugins = new TreeSet<>();
    public final Set<String> accessWidenerClasses = new TreeSet<>();
    public final boolean refmapPresent;
    public final int minClassVersion;
    public final int classCount;

    private ModProfile(String inputJar, boolean refmapPresent, int minClassVersion, int classCount) {
        this.inputJar = inputJar;
        this.refmapPresent = refmapPresent;
        this.minClassVersion = minClassVersion;
        this.classCount = classCount;
    }

    /** Classes that must stay readable: entrypoints, mixin classes and accessWidener owners. */
    public Set<String> readableClasses() {
        Set<String> keep = new TreeSet<>();
        keep.addAll(entrypoints);
        keep.addAll(mixinClasses);
        keep.addAll(mixinPlugins);
        keep.addAll(accessWidenerClasses);
        return keep;
    }

    public static ModProfile fromJar(Path jarPath) throws IOException {
        try (ZipFile zip = new ZipFile(jarPath.toFile())) {
            String meta = null;
            ZipEntry metaEntry = zip.getEntry("fabric.mod.json");
            if (metaEntry != null) {
                try (InputStream in = zip.getInputStream(metaEntry)) {
                    meta = new String(in.readAllBytes(), StandardCharsets.UTF_8);
                }
            }
            if (meta == null) {
                return new ModProfile(jarPath.getFileName().toString(), false, 0, 0);
            }

            List<String> mixinConfigs = new ArrayList<>();
            MatcherFinder.find(meta, "mixins", mixinConfigs);
            MatcherFinder.find(meta, "client", mixinConfigs);

            Set<String> entrypoints = new TreeSet<>();
            for (String name : MatcherFinder.classNames(meta)) {
                if (name.contains("/") && !name.contains("-")) {
                    entrypoints.add(name);
                }
            }

            Set<String> mixinClasses = new TreeSet<>();
            // Inner classes declared inside a mixin. Mixin merges them into the target class and
            // derives the merged name from the mixin's own inner-class name, so they must be kept
            // exactly like the mixin itself (readable, never renamed). Only top-level names appear
            // in the mixin JSON, which is why these are collected separately below.
            Set<String> mixinInnerClasses = new TreeSet<>();
            Set<String> profilePlugins = new TreeSet<>();
            boolean refmapPresent = false;
            for (String config : mixinConfigs) {
                if (!config.endsWith(".json")) {
                    continue;
                }
                ZipEntry entry = zip.getEntry(config);
                if (entry == null) {
                    continue;
                }
                String json;
                try (InputStream in = zip.getInputStream(entry)) {
                    json = new String(in.readAllBytes(), StandardCharsets.UTF_8);
                }
                if (json.contains("\"refmap\"")) {
                    refmapPresent = true;
                }
                String plugin = MatcherFinder.firstString(json, "plugin");
                if (plugin != null && !plugin.isBlank()) {
                    // Mixin instantiates this class by name before any mixin class is read, so it
                    // must stay readable and keep its name (S3' adds its own plugin on top).
                    profilePlugins.add(plugin.trim().replace('.', '/'));
                }
                String pkg = MatcherFinder.firstString(json, "package");
                for (String name : MatcherFinder.arrayStrings(json, "mixins")) {
                    mixinClasses.add(join(pkg, name));
                }
                for (String name : MatcherFinder.arrayStrings(json, "client")) {
                    mixinClasses.add(join(pkg, name));
                }
            }
            for (ZipEntry entry : java.util.Collections.list(zip.entries())) {
                if (entry.getName().endsWith(".refmap.json")) {
                    refmapPresent = true;
                    break;
                }
            }

            Set<String> awClasses = new TreeSet<>();
            String awName = MatcherFinder.firstString(meta, "accessWidener");
            if (awName != null && !awName.isBlank()) {
                ZipEntry aw = zip.getEntry(awName);
                if (aw != null) {
                    try (InputStream in = zip.getInputStream(aw)) {
                        for (String line : new String(in.readAllBytes(), StandardCharsets.UTF_8)
                                .split("\\R")) {
                            String trimmed = line.trim();
                            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                                continue;
                            }
                            String[] parts = trimmed.split("\\s+");
                            if (parts.length < 3) {
                                continue;
                            }
                            String owner = parts[2];
                            int cut = owner.indexOf('(');
                            if (cut >= 0) {
                                owner = owner.substring(0, cut);
                            }
                            owner = owner.replace('.', '/');
                            if (!owner.isEmpty()) {
                                awClasses.add(owner);
                            }
                        }
                    }
                }
            }

            int minVersion = Integer.MAX_VALUE;
            int classCount = 0;
            for (ZipEntry entry : java.util.Collections.list(zip.entries())) {
                if (!entry.getName().endsWith(".class")) {
                    continue;
                }
                // Attach inner classes to their declaring mixin (framework rule: anything Mixin
                // copies into a target must keep its name). Measured failure without this:
                // NoClassDefFoundError net/minecraft/class_425$GlState$<hash> when the renamed
                // inner class could no longer be matched up by Mixin.
                String internal = entry.getName().substring(0, entry.getName().length() - 6);
                for (String mixin : mixinClasses) {
                    if (internal.startsWith(mixin + "$")) {
                        mixinInnerClasses.add(internal);
                        break;
                    }
                }
                classCount++;
                try (InputStream in = zip.getInputStream(entry)) {
                    byte[] head = in.readNBytes(8);
                    if (head.length >= 8) {
                        int version = ((head[6] & 0xff) << 8) | (head[7] & 0xff);
                        minVersion = Math.min(minVersion, version);
                    }
                }
            }
            if (minVersion == Integer.MAX_VALUE) {
                minVersion = 0;
            }

            ModProfile profile = new ModProfile(jarPath.getFileName().toString(),
                    refmapPresent, minVersion, classCount);
            profile.entrypoints.addAll(entrypoints);
            profile.mixinClasses.addAll(mixinClasses);
            profile.mixinClasses.addAll(mixinInnerClasses);
            profile.mixinPlugins.addAll(profilePlugins);
            profile.accessWidenerClasses.addAll(awClasses);
            return profile;
        }
    }

    private static String join(String pkg, String simple) {
        String normalized = simple.replace('.', '/');
        if (pkg == null || pkg.isBlank()) {
            return normalized;
        }
        return pkg.replace('.', '/') + "/" + normalized;
    }

    public void writeJson(Path output) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"inputJar\": \"").append(escape(inputJar)).append("\",\n");
        sb.append("  \"classCount\": ").append(classCount).append(",\n");
        sb.append("  \"minClassVersion\": ").append(minClassVersion).append(",\n");
        sb.append("  \"refmapPresent\": ").append(refmapPresent).append(",\n");
        sb.append("  \"entrypoints\": ").append(array(entrypoints)).append(",\n");
        sb.append("  \"mixinClasses\": ").append(array(mixinClasses)).append(",\n");
        sb.append("  \"accessWidenerClasses\": ").append(array(accessWidenerClasses)).append("\n");
        sb.append("}\n");
        Files.createDirectories(output.toAbsolutePath().getParent());
        Files.writeString(output, sb.toString(), StandardCharsets.UTF_8);
    }

    private static String array(Set<String> values) {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (String value : values) {
            if (!first) {
                sb.append(", ");
            }
            first = false;
            sb.append('"').append(escape(value)).append('"');
        }
        return sb.append(']').toString();
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    /** Small JSON scanner: avoids adding a JSON dependency to the obfuscator. */
    public static final class MatcherFinder {
        private MatcherFinder() {
        }

        static List<String> classNames(String meta) {
            List<String> names = new ArrayList<>();
            java.util.regex.Matcher m = java.util.regex.Pattern
                    .compile("\"((?:[a-zA-Z_][a-zA-Z0-9_]*\\.)+[A-Za-z0-9_$]+)\"")
                    .matcher(meta);
            while (m.find()) {
                names.add(m.group(1).replace('.', '/'));
            }
            return names;
        }

        public static String firstString(String json, String key) {
            java.util.regex.Matcher m = java.util.regex.Pattern
                    .compile("\"" + key + "\"\\s*:\\s*\"([^\"]+)\"").matcher(json);
            return m.find() ? m.group(1) : null;
        }

        static List<String> arrayStrings(String json, String key) {
            List<String> values = new ArrayList<>();
            java.util.regex.Matcher m = java.util.regex.Pattern
                    .compile("\"" + key + "\"\\s*:\\s*\\[(.*?)\\]", java.util.regex.Pattern.DOTALL)
                    .matcher(json);
            if (!m.find()) {
                return values;
            }
            java.util.regex.Matcher item = java.util.regex.Pattern.compile("\"([^\"]+)\"")
                    .matcher(m.group(1));
            while (item.find()) {
                values.add(item.group(1));
            }
            return values;
        }

        static void find(String json, String key, List<String> out) {
            for (String value : arrayStrings(json, key)) {
                out.add(value);
            }
        }
    }
}
