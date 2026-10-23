package dev.chimera.core;

import dev.chimera.crypto.Crypto;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/** Mutable per-build state passed to every transformer. */
public final class TransformContext {
    public final ChimeraConfig config;
    public final byte[] envSalt;
    public final byte[] kek;
    public final ClassPool pool;
    public final ResourceSink sink;
    public final Stats stats;
    public final String buildId;

    /**
     * Set by a transformer that changed operand-stack/local shapes without changing branch
     * structure (e.g. entangle injects a linear prologue that stores new locals). The engine then
     * recomputes StackMapTable instead of reusing the original one.
     */
    private final java.util.Set<String> framesRequiredClasses = new java.util.HashSet<>();

    private final AtomicInteger stringSeq = new AtomicInteger();
    private final AtomicInteger chunkSeq = new AtomicInteger();
    private final Map<Integer, String> strings = new LinkedHashMap<>();
    private final Map<String, String> classHashes = new LinkedHashMap<>();
    private final List<NativeTemplate> nativeTemplates = new ArrayList<>();

    public TransformContext(ChimeraConfig config, byte[] envSalt, byte[] kek,
                            ClassPool pool, ResourceSink sink, Stats stats, String buildId) {
        this.config = config;
        this.envSalt = envSalt;
        this.kek = kek;
        this.pool = pool;
        this.sink = sink;
        this.stats = stats;
        this.buildId = buildId;
    }

    public void markFramesRequired(String internalName) {
        synchronized (framesRequiredClasses) {
            framesRequiredClasses.add(internalName);
        }
    }

    public boolean framesRequired(String internalName) {
        synchronized (framesRequiredClasses) {
            return framesRequiredClasses.contains(internalName);
        }
    }

    public int registerString(String value) {
        int id = stringSeq.getAndIncrement();
        strings.put(id, value);
        return id;
    }

    public Map<Integer, String> strings() {
        return Collections.unmodifiableMap(strings);
    }

    public int nextChunkId() {
        return chunkSeq.getAndIncrement();
    }

    public byte[] deriveItemKey(String kind, int id) {
        return Crypto.hkdf(kek, envSalt,
                ("chimera/v1/" + kind + "/" + id).getBytes(StandardCharsets.UTF_8), 32);
    }

    public void addNative(NativeTemplate t) {
        nativeTemplates.add(t);
    }

    public List<NativeTemplate> nativeTemplates() {
        return Collections.unmodifiableList(nativeTemplates);
    }

    public void recordClassHash(String path, String hash) {
        classHashes.put(path, hash);
    }

    public Map<String, String> classHashes() {
        return Collections.unmodifiableMap(classHashes);
    }

    /** Serializes the encrypted string table consumed by ChimeraRuntime.decryptStr. */
    public byte[] encodeStringTable() {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bos);
            out.writeInt(0x43485331); // CHS1
            out.writeInt(1);
            out.writeInt(strings.size());
            for (Map.Entry<Integer, String> e : strings.entrySet()) {
                int id = e.getKey();
                byte[] plain = e.getValue().getBytes(StandardCharsets.UTF_8);
                byte[] nonce = Crypto.random(12);
                byte[] key = deriveItemKey("str", id);
                byte[] ct = Crypto.aesGcmEncrypt(key, nonce, plain,
                        ("str/" + id).getBytes(StandardCharsets.UTF_8));
                out.writeInt(id);
                out.writeInt(nonce.length);
                out.write(nonce);
                out.writeInt(ct.length);
                out.write(ct);
            }
            out.flush();
            return bos.toByteArray();
        } catch (Exception ex) {
            throw new IllegalStateException("encodeStringTable failed", ex);
        }
    }
}
