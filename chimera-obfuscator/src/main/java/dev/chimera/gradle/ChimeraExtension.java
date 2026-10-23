package dev.chimera.gradle;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/** Gradle DSL: chimera { inputJar = file(...); outputJar = file(...); contentKey = "..." } */
public class ChimeraExtension {
    public File inputJar;
    public File outputJar;
    public File nativeOutDir;
    public File nativeLibDir;
    /**
     * Optional OpenSSL static build directory (contains {@code include/openssl} and
     * {@code lib/libcrypto.a}). When set, generated JNI templates are linked with
     * {@code -static -lcrypto -lssl}, so the shipped DLL has no OpenSSL DLL dependency.
     */
    public File opensslStaticDir;
    public String nativeCompiler = "gcc";
    /** KI-28: 32-byte product ResourceKey as 64 hex chars (primary build-time encryption key). */
    public String resourceKeyHex;
    /** Release build: ResourceKey is mandatory and the legacy content-key fallback is rejected. */
    public boolean release;
    /** Deprecated dev fallback (legacy global content key). */
    public String contentKey;
    public String authServer;
    public String authPubkey;
    public long authHeartbeatMs = 300_000L;
    public String authPin;
    public boolean strictFabric = true;
    public boolean rename = true;
    public boolean encryptStrings = true;
    public boolean fragmentMethods = true;
    public boolean nativeStubs = true;
    public boolean integrityManifest = true;
    public boolean vm = true;
    public boolean honeypot = true;
    public boolean entangle = true;
    public boolean verbose = false;
    public List<String> excludes = new ArrayList<>();

    public File getInputJar() { return inputJar; }
    public void setInputJar(File inputJar) { this.inputJar = inputJar; }
    public File getOutputJar() { return outputJar; }
    public void setOutputJar(File outputJar) { this.outputJar = outputJar; }
    public File getNativeOutDir() { return nativeOutDir; }
    public void setNativeOutDir(File nativeOutDir) { this.nativeOutDir = nativeOutDir; }
    public File getNativeLibDir() { return nativeLibDir; }
    public void setNativeLibDir(File nativeLibDir) { this.nativeLibDir = nativeLibDir; }
    public File getOpensslStaticDir() { return opensslStaticDir; }
    public void setOpensslStaticDir(File opensslStaticDir) { this.opensslStaticDir = opensslStaticDir; }
    public String getNativeCompiler() { return nativeCompiler; }
    public void setNativeCompiler(String nativeCompiler) { this.nativeCompiler = nativeCompiler; }
    public String getResourceKeyHex() { return resourceKeyHex; }
    public void setResourceKeyHex(String resourceKeyHex) { this.resourceKeyHex = resourceKeyHex; }
    public boolean isRelease() { return release; }
    public void setRelease(boolean release) { this.release = release; }
    public String getContentKey() { return contentKey; }
    public void setContentKey(String contentKey) { this.contentKey = contentKey; }
    public String getAuthServer() { return authServer; }
    public void setAuthServer(String authServer) { this.authServer = authServer; }
    public String getAuthPubkey() { return authPubkey; }
    public void setAuthPubkey(String authPubkey) { this.authPubkey = authPubkey; }
    public long getAuthHeartbeatMs() { return authHeartbeatMs; }
    public void setAuthHeartbeatMs(long authHeartbeatMs) { this.authHeartbeatMs = authHeartbeatMs; }
    public String getAuthPin() { return authPin; }
    public void setAuthPin(String authPin) { this.authPin = authPin; }
    public boolean isRename() { return rename; }
    public void setRename(boolean rename) { this.rename = rename; }
    public boolean isVm() { return vm; }
    public void setVm(boolean vm) { this.vm = vm; }
    public boolean isHoneypot() { return honeypot; }
    public void setHoneypot(boolean honeypot) { this.honeypot = honeypot; }
    public boolean isEntangle() { return entangle; }
    public void setEntangle(boolean entangle) { this.entangle = entangle; }
    public List<String> getExcludes() { return excludes; }
    public void setExcludes(List<String> excludes) { this.excludes = excludes; }
}
