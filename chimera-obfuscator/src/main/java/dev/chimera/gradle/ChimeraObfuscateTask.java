package dev.chimera.gradle;

import dev.chimera.core.ChimeraConfig;
import dev.chimera.core.ChimeraEngine;
import dev.chimera.core.Stats;
import dev.chimera.crypto.Crypto;
import org.gradle.api.DefaultTask;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputDirectory;
import org.gradle.api.tasks.InputFile;
import org.gradle.api.tasks.Internal;
import org.gradle.api.tasks.Optional;
import org.gradle.api.tasks.OutputFile;
import org.gradle.api.tasks.TaskAction;

import java.io.File;
import java.nio.charset.StandardCharsets;

/** Gradle task that runs the Chimera engine with the configured extension values. */
public abstract class ChimeraObfuscateTask extends DefaultTask {
    private ChimeraExtension extension;

    @Internal
    public ChimeraExtension getExtension() {
        return extension;
    }

    public void setExtension(ChimeraExtension extension) {
        this.extension = extension;
    }

    // Up-to-date checking: without these annotations Gradle would always consider the task
    // up-to-date and silently skip re-obfuscation after a source change.

    @InputFile
    @Optional
    public File getInputJarFile() {
        return extension == null ? null : extension.inputJar;
    }

    @OutputFile
    @Optional
    public File getOutputJarFile() {
        return extension == null ? null : extension.outputJar;
    }

    @InputDirectory
    @Optional
    public File getNativeOutDirFile() {
        return extension == null ? null : extension.nativeOutDir;
    }

    @Input
    public boolean isRenameEnabled() {
        return extension == null || extension.rename;
    }

    @Input
    public boolean isVmEnabled() {
        return extension == null || extension.vm;
    }

    @Input
    public boolean isHoneypotEnabled() {
        return extension == null || extension.honeypot;
    }

    @Input
    public boolean isEntangleEnabled() {
        return extension == null || extension.entangle;
    }

    /** KI-28: fingerprints (not the secret) of the ResourceKey so incremental builds invalidate. */
    @Input
    public String getResourceKeyFingerprint() {
        String hex = extension == null ? null : extension.resourceKeyHex;
        if (hex == null || hex.isBlank()) hex = System.getenv("CHIMERA_RESOURCE_KEY_HEX");
        if (hex == null || hex.isBlank()) return "none";
        return Crypto.hex(Crypto.sha256(hex.getBytes(StandardCharsets.UTF_8)));
    }

    @Input
    public boolean isReleaseBuild() {
        if (extension != null && extension.release) return true;
        Object property = getProject().findProperty("chimera.release");
        return property != null && property.toString().equalsIgnoreCase("true");
    }

    @TaskAction
    public void obfuscate() throws Exception {
        ChimeraExtension extension = getExtension();
        if (extension == null) throw new IllegalStateException("chimera extension missing");
        ChimeraConfig cfg = new ChimeraConfig();
        cfg.inputJar = extension.inputJar.toPath();
        cfg.outputJar = extension.outputJar.toPath();
        if (extension.nativeOutDir != null) cfg.nativeOutDir = extension.nativeOutDir.toPath();
        cfg.release = isReleaseBuild();
        // KI-28: ResourceKey is the primary build key; the legacy contentKey is dev-only.
        String resourceKeyHex = extension.resourceKeyHex;
        if (resourceKeyHex == null || resourceKeyHex.isBlank()) {
            resourceKeyHex = System.getenv("CHIMERA_RESOURCE_KEY_HEX");
        }
        if (resourceKeyHex != null && !resourceKeyHex.isBlank()) {
            String compact = resourceKeyHex.replaceAll("\\s", "");
            if (!compact.matches("[0-9a-fA-F]{64}")) {
                throw new IllegalStateException(
                        "chimera.resourceKeyHex must be exactly 64 hex characters (32-byte ResourceKey)");
            }
            cfg.resourceKeyMaterial = Crypto.unhex(compact);
        } else if (extension.contentKey != null) {
            cfg.keyMaterial = extension.contentKey.matches("[0-9a-fA-F]{16,128}")
                    ? Crypto.unhex(extension.contentKey)
                    : Crypto.sha256(extension.contentKey.getBytes(StandardCharsets.UTF_8));
        } else if (cfg.release) {
            throw new IllegalStateException("chimera.resourceKeyHex is required for release builds (KI-28)");
        }
        cfg.authServer = extension.authServer;
        cfg.authPubkey = extension.authPubkey;
        cfg.authHeartbeatMs = extension.authHeartbeatMs;
        cfg.authPin = extension.authPin;
        cfg.strictFabric = extension.strictFabric;
        cfg.rename = extension.rename;
        cfg.encryptStrings = extension.encryptStrings;
        cfg.fragmentMethods = extension.fragmentMethods;
        cfg.nativeStubs = extension.nativeStubs;
        cfg.integrityManifest = extension.integrityManifest;
        cfg.vm = extension.vm;
        cfg.honeypot = extension.honeypot;
        cfg.entangle = extension.entangle;
        cfg.verbose = extension.verbose;
        cfg.excludes.addAll(extension.excludes);
        Stats stats = new ChimeraEngine(cfg).run();
        getLogger().lifecycle("[chimera] " + stats);
        getLogger().lifecycle("[chimera] output: {}", cfg.outputJar.toAbsolutePath());
    }
}
