package dev.chimera.core;

import dev.chimera.attach.AgentCipher;
import dev.chimera.transform.encrypt.ClassPayloadBuilder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * S2: class-body encryption (CHENC1) and the self-attaching agent jar.
 *
 * <p>The agent jar is generated per build and embedded in the mod jar. It registers a
 * {@code ClassFileTransformer} through the {@code jdk.attach} helper process at {@code preLaunch}.
 * Encrypted entries keep their normal (invisible) names, so the class loader reads the ciphertext
 * and the transformer swaps in the plaintext at define time.</p>
 *
 * <p>P1-1: the jar carries <b>no</b> key material. The CHENC1 key is derived inside native from
 * the ResourceKey held by the authorized SessionHandle (see {@code nativeDeriveClassKey}), so
 * extracting anything from this jar yields ciphertext that cannot be decrypted without a licence.</p>
 */
public final class ClassEncryptor {

    public static final String AGENT_JAR_RESOURCE = "chimera/attach/agent.jar";
    public static final String AGENT_CLASS = "dev.chimera.attach.AttachAgent";
    public static final String AGENT_STATE = "dev.chimera.attach.AgentState";
    public static final String AGENT_HELPER = "dev.chimera.attach.Attacher";
    public static final String SENTINEL_BINARY = "dev.chimera.probe.ChimeraSentinel";

    private static final byte[] AGENT_MANIFEST = ("Manifest-Version: 1.0\r\n"
            + "Agent-Class: " + AGENT_CLASS + "\r\n"
            + "Can-Retransform-Classes: true\r\n"
            + "Can-Redefine-Classes: false\r\n\r\n").getBytes(StandardCharsets.UTF_8);

    private static final String AGENT_PACKAGE = "dev/chimera/attach/";
    private static final String[] REQUIRED_AGENT_CLASSES = {
            "dev/chimera/attach/AgentCipher.class",
            "dev/chimera/attach/AgentState.class",
            "dev/chimera/attach/ClassDecryptTransformer.class",
            "dev/chimera/attach/AttachAgent.class",
            "dev/chimera/attach/Attacher.class",
            "dev/chimera/attach/FabricHook.class",
            "dev/chimera/attach/FabricByteHookTransformer.class"
    };

    private ClassEncryptor() {
    }

    /** Which classes must stay plaintext (entrypoints, mixins, runtime, excluded prefixes). */
    public record Keep(Set<String> exact, Set<String> prefixes, boolean encryptMixins) {
        /** True when the class must not be encrypted. */
        public boolean keep(String internalName, byte[] plainBytes) {
            if (internalName.startsWith("dev/chimera/") && !internalName.startsWith("dev/chimera/probe/")) {
                return true;
            }
            // M10: generated bootstrap owners are invokedynamic link targets; the member table
            // (chimera/indy/members.bin) is a non-class resource and never passes through here,
            // but the Bsm* classes must stay plaintext or no rewritten call site can link.
            if (internalName.startsWith("chimera/indy/")) {
                return true;
            }
            if (exact.contains(internalName)) {
                return true;
            }
            for (String kept : exact) {
                if (internalName.startsWith(kept + "$")) {
                    return true;
                }
            }
            for (String prefix : prefixes) {
                if (!prefix.isEmpty() && internalName.startsWith(prefix)) {
                    return true;
                }
            }
            if (plainBytes == null || plainBytes.length < 10) {
                return false;
            }
            if (encryptMixins) {
                // S3': Mixin reads mixin bytes through FabricLauncher.getClassByteArray(name, true),
                // which the agent hook decrypts, so mixin classes need no plaintext copy at all.
                return false;
            }
            return ClassPayloadBuilder.isMixinClass(plainBytes);
        }
    }

    /** Builds the keep-set; {@code renames} maps original -> final internal names. */
    public static Keep plan(ChimeraConfig config, ModProfile profile,
                            Map<String, String> renames, Set<String> fallbackEntrypoints,
                            Set<String> extraPlaintext) {
        Set<String> exact = new TreeSet<>();
        for (String extra : extraPlaintext) {
            // Mixin config plugins are instantiated by name before the agent can exist: they must
            // never be ciphertext (and never be renamed) or the config fails at select time.
            exact.add(renames.getOrDefault(extra, extra));
        }
        if (profile != null) {
            for (String entrypoint : profile.entrypoints) {
                exact.add(renames.getOrDefault(entrypoint, entrypoint));
            }
            if (!config.encryptMixins) {
                for (String mixin : profile.mixinClasses) {
                    exact.add(renames.getOrDefault(mixin, mixin));
                }
            }
        }
        for (String entrypoint : fallbackEntrypoints) {
            exact.add(renames.getOrDefault(entrypoint, entrypoint));
        }
        // Bootstrap mode (non-Fabric input, e.g. the engine itself): the manifest Main-Class is
        // loaded by the JVM before any Java code runs, so it must stay plaintext. Everything
        // else loads through the attach agent.
        if (config.mainClassKeep) {
            Set<String> manifestMain = manifestMainClasses(config.inputJar, renames);
            exact.addAll(manifestMain);
            if (!manifestMain.isEmpty()) {
                System.err.println("[chimera] class encryption keep (manifest main): "
                        + manifestMain.size());
            }
        }
        Set<String> prefixes = new TreeSet<>();
        prefixes.addAll(config.excludes);
        return new Keep(exact, prefixes, config.encryptMixins);
    }

    /** Resolves the input jar's Main-Class through the rename table to final internal names. */
    private static Set<String> manifestMainClasses(java.nio.file.Path inputJar,
                                                    Map<String, String> renames) {
        Set<String> out = new TreeSet<>();
        try (java.util.jar.JarFile jar = new java.util.jar.JarFile(inputJar.toFile())) {
            java.util.jar.Attributes attrs = jar.getManifest().getMainAttributes();
            String main = attrs.getValue("Main-Class");
            if (main != null && !main.isBlank()) {
                String internal = main.trim().replace('.', '/');
                out.add(renames.getOrDefault(internal, internal));
            }
        } catch (Throwable ignored) {
            // no manifest or unreadable: nothing to keep
        }
        return out;
    }

    /** Encrypts a class body with the build key; AAD is the class internal name. */
    public static byte[] encrypt(byte[] plain, byte[] key, String internalName) {
        return AgentCipher.encrypt(plain, key, internalName);
    }

    /**
     * Collects every class of the agent package (including anonymous/nested classes) from this
     * build's own artifact, so the generated agent jar never misses a synthetic class.
     */
    public static Map<String, byte[]> collectAgentClasses() {
        Map<String, byte[]> out = new java.util.TreeMap<>();
        try {
            java.security.CodeSource source = ClassEncryptor.class.getProtectionDomain().getCodeSource();
            java.net.URL location = source == null ? null : source.getLocation();
            if (location == null) {
                throw new IllegalStateException("own artifact location unavailable");
            }
            java.nio.file.Path path = java.nio.file.Path.of(location.toURI());
            if (java.nio.file.Files.isDirectory(path)) {
                try (java.util.stream.Stream<java.nio.file.Path> files = java.nio.file.Files.walk(path.resolve(AGENT_PACKAGE))) {
                    for (java.nio.file.Path file : (Iterable<java.nio.file.Path>) files::iterator) {
                        if (!file.toString().endsWith(".class")) {
                            continue;
                        }
                        String relative = path.relativize(file).toString().replace('\\', '/');
                        out.put(relative, java.nio.file.Files.readAllBytes(file));
                    }
                }
            } else {
                try (java.util.zip.ZipFile zip = new java.util.zip.ZipFile(path.toFile())) {
                    java.util.Enumeration<? extends java.util.zip.ZipEntry> entries = zip.entries();
                    while (entries.hasMoreElements()) {
                        java.util.zip.ZipEntry entry = entries.nextElement();
                        if (!entry.getName().startsWith(AGENT_PACKAGE) || !entry.getName().endsWith(".class")) {
                            continue;
                        }
                        try (java.io.InputStream in = zip.getInputStream(entry)) {
                            out.put(entry.getName(), in.readAllBytes());
                        }
                    }
                }
            }
        } catch (Exception e) {
            throw new IllegalStateException("cannot collect agent classes", e);
        }
        return verifyAgentClasses(out);
    }

    /**
     * Bootstrap variant: collects the agent package from the build's input class map instead of
     * this engine's own artifact. Returns null when the input does not contain the attach
     * package (a normal mod jar), so the caller falls back to the artifact scan above.
     *
     * <p>Self-protected builds need this: the engine's own artifact carries renamed attach
     * classes and string-synced name constants, so neither the artifact scan nor the embedded
     * agent jar fallback can produce a fresh agent with canonical names. The input map (the
     * plain all-jar the engine was built from... or any jar embedding the attach package)
     * holds the pre-rename bytes with original names.</p>
     */
    public static Map<String, byte[]> collectAgentClasses(Map<String, byte[]> inputClasses) {
        if (inputClasses == null) {
            return null;
        }
        Map<String, byte[]> out = new java.util.TreeMap<>();
        for (Map.Entry<String, byte[]> entry : inputClasses.entrySet()) {
            if (entry.getKey().startsWith(AGENT_PACKAGE) && entry.getKey().endsWith(".class")) {
                out.put(entry.getKey(), entry.getValue());
            }
        }
        if (!out.containsKey("dev/chimera/attach/AgentCipher.class")) {
            return null;
        }
        return verifyAgentClasses(out);
    }

    private static Map<String, byte[]> verifyAgentClasses(Map<String, byte[]> collected) {
        Map<String, byte[]> out = collected;
        for (String required : REQUIRED_AGENT_CLASSES) {
            if (!out.containsKey(required)) {
                // Self-protected bootstrap: this engine's own attach classes were renamed
                // (invisible naming) when the engine protected itself, so the canonical
                // dev/chimera/attach/ paths no longer exist in this artifact. Recover them
                // from the embedded agent jar of the previous build instead.
                byte[] carried = readCarriedAgentClass(required);
                if (carried == null) {
                    throw new IllegalStateException("agent class missing from build: " + required);
                }
                out.put(required, carried);
            }
        }
        return out;
    }

    /**
     * Bootstrap fallback: pulls an agent class out of the agent jar embedded in this very
     * artifact (chimera/attach/agent.jar), the one the previous Chimera build produced. Those
     * copies are pre-rename, so they carry exactly the dev/chimera/attach names the new agent
     * jar needs. Non-bootstrap builds never reach this path.
     */
    private static byte[] readCarriedAgentClass(String required) {
        try (InputStream in = ClassEncryptor.class.getResourceAsStream(AGENT_JAR_RESOURCE)) {
            if (in == null) {
                return null;
            }
            byte[] jarBytes = in.readAllBytes();
            try (java.util.zip.ZipInputStream zis =
                         new java.util.zip.ZipInputStream(new ByteArrayInputStream(jarBytes))) {
                java.util.zip.ZipEntry entry;
                while ((entry = zis.getNextEntry()) != null) {
                    if (required.equals(entry.getName())) {
                        return zis.readAllBytes();
                    }
                }
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    /** Builds the embedded agent jar (classes + manifest). */
    public static byte[] buildAgentJar(Map<String, byte[]> agentClasses) {
        return buildAgentJar(agentClasses, null);
    }

    /**
     * Builds the self-attaching agent jar.
     *
     * <p>P0-3a: when {@code protectedNames} is non-null, the exact set of class bodies that were
     * encrypted in this build is embedded as {@code chimera/attach/protected.txt}. The agent uses
     * it to enforce ciphertext-mandatory loading: a class on this list that arrives as plaintext
     * means someone dumped decrypted bodies and put them back into the jar, and the process must
     * die instead of running happily without a licence. Dev builds pass {@code null} and keep the
     * old lenient behaviour.</p>
     *
     * <p>P1-1: the jar deliberately contains no key material. The agent derives the CHENC1 key
     * from the native SessionHandle, so a jar-only attacker cannot decrypt anything.</p>
     */
    public static byte[] buildAgentJar(Map<String, byte[]> agentClasses,
                                       java.util.Set<String> protectedNames) {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            try (ZipOutputStream zos = new ZipOutputStream(buffer)) {
                put(zos, "META-INF/MANIFEST.MF", AGENT_MANIFEST);
                for (Map.Entry<String, byte[]> entry : agentClasses.entrySet()) {
                    put(zos, entry.getKey(), entry.getValue());
                }
                if (protectedNames != null && !protectedNames.isEmpty()) {
                    // Store digests, not names: the plaintext list told an attacker exactly which
                    // classes are protected. A 128-bit truncation of SHA-256 is enough for an
                    // exact-membership test and reveals nothing about the names.
                    StringBuilder sb = new StringBuilder(protectedNames.size() * 40);
                    java.security.MessageDigest digest =
                            java.security.MessageDigest.getInstance("SHA-256");
                    for (String name : protectedNames) {
                        byte[] h = digest.digest(name.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                        StringBuilder hex = new StringBuilder(32);
                        for (int i = 0; i < 16; i++) {
                            hex.append(Character.forDigit((h[i] >> 4) & 0xF, 16));
                            hex.append(Character.forDigit(h[i] & 0xF, 16));
                        }
                        sb.append(hex).append('\n');
                    }
                    put(zos, "chimera/attach/protected.txt",
                            sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
                }
            }
            return buffer.toByteArray();
        } catch (java.io.IOException | java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("agent jar generation failed", e);
        }
    }

    private static void put(ZipOutputStream zos, String name, byte[] data) throws java.io.IOException {
        ZipEntry entry = new ZipEntry(name);
        entry.setTime(0L);
        zos.putNextEntry(entry);
        zos.write(data);
        zos.closeEntry();
    }

    /** Parses entrypoint class names out of fabric.mod.json as a fallback keep-set. */
    public static Set<String> entrypointsFromMetadata(byte[] fabricJson) {
        Set<String> out = new TreeSet<>();
        if (fabricJson == null) {
            return out;
        }
        String text = new String(fabricJson, StandardCharsets.UTF_8);
        java.util.regex.Matcher matcher = java.util.regex.Pattern
                .compile("\"((?:[a-z_][a-z0-9_]*\\.)+[A-Za-z0-9_$]+)\"")
                .matcher(text);
        while (matcher.find()) {
            out.add(matcher.group(1).replace('.', '/'));
        }
        return out;
    }

    /** Resource names of the agent jar entries, for diagnostics. */
    public static Map<String, String> agentLayout() {
        Map<String, String> out = new LinkedHashMap<>();
        out.put("manifest", AGENT_CLASS);
        out.put("classes", String.valueOf(REQUIRED_AGENT_CLASSES.length));
        return out;
    }
}
