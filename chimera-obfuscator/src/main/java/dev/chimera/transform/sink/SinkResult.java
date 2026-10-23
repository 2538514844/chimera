package dev.chimera.transform.sink;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * Immutable snapshot emitted by {@link NativeSinkTransformer}: selected methods (including their
 * original {@link org.objectweb.asm.tree.MethodNode}), per-reason skip counters and the generated
 * JNI artifacts.
 *
 * <p>Every accessor is deterministic: selected methods are sorted by
 * {@code owner, name, descriptor} and skip counters by reason label, so two identical selection sets
 * always produce byte-identical manifests/snippets, regardless of class visitation order. (Whether
 * the selection set itself is order-independent under a binding build-wide budget is documented on
 * {@link NativeSinkTransformer.Options#maxMethodsPerBuild()}.)</p>
 */
public final class SinkResult {

    private final List<SinkSelectedMethod> methods;
    private final Map<String, Integer> skippedByReason;
    private final int methodsVisited;
    private final int classesVisited;
    private final int mixinClassesSkipped;

    public SinkResult(List<SinkSelectedMethod> methods,
                      Map<String, Integer> skippedByReason,
                      int methodsVisited,
                      int classesVisited,
                      int mixinClassesSkipped) {
        Objects.requireNonNull(methods, "methods");
        List<SinkSelectedMethod> sorted = new ArrayList<>(methods);
        sorted.sort(Comparator.comparing(SinkSelectedMethod::owner)
                .thenComparing(SinkSelectedMethod::name)
                .thenComparing(SinkSelectedMethod::descriptor));
        this.methods = List.copyOf(sorted);
        this.skippedByReason = skippedByReason == null
                ? Map.of()
                : Collections.unmodifiableMap(new TreeMap<>(skippedByReason));
        if (methodsVisited < 0 || classesVisited < 0 || mixinClassesSkipped < 0) {
            throw new IllegalArgumentException("stat counters must not be negative");
        }
        this.methodsVisited = methodsVisited;
        this.classesVisited = classesVisited;
        this.mixinClassesSkipped = mixinClassesSkipped;
    }

    /** Selected methods, canonically sorted by owner/name/descriptor. */
    public List<SinkSelectedMethod> selectedMethods() {
        return methods;
    }

    /** One generated JNI function source per selected method, in canonical order. */
    public List<String> generatedFunctionSources() {
        List<String> out = new ArrayList<>(methods.size());
        for (SinkSelectedMethod method : methods) {
            out.add(method.cppSource());
        }
        return List.copyOf(out);
    }

    public Map<String, Integer> skippedByReason() {
        return skippedByReason;
    }

    public int selected() {
        return methods.size();
    }

    public int generatedFunctions() {
        return methods.size();
    }

    public int skipped() {
        int total = 0;
        for (int value : skippedByReason.values()) {
            total += value;
        }
        return total;
    }

    public int methodsVisited() {
        return methodsVisited;
    }

    public int classesVisited() {
        return classesVisited;
    }

    public int mixinClassesSkipped() {
        return mixinClassesSkipped;
    }

    /** {@code selected + skipped}; equals {@link #methodsVisited()} for a consistent snapshot. */
    public int accountedMethods() {
        return selected() + skipped();
    }

    /** One line per selected method: {@code owner\tname\tdesc\tsignature}. */
    public String encodeSinkManifest() {
        return SinkCodegen.manifest(methods);
    }

    /** RegisterNatives wiring, including a guarded standalone {@code JNI_OnLoad}. */
    public String registerNativesSnippet() {
        return SinkCodegen.registration(methods, true);
    }

    /**
     * RegisterNatives wiring. Use {@code includeJniOnLoad=false} when the library already exports
     * {@code JNI_OnLoad}; call {@code chimera_sink_register_all(env)} from it instead.
     */
    public String registerNativesSnippet(boolean includeJniOnLoad) {
        return SinkCodegen.registration(methods, includeJniOnLoad);
    }

    /** Complete translation unit: includes + generated JNI functions + registration wiring. */
    public String cppUnit() {
        return SinkCodegen.unit(methods, true);
    }

    /** Translation unit without the standalone {@code JNI_OnLoad} (for existing native libs). */
    public String cppUnit(boolean includeJniOnLoad) {
        return SinkCodegen.unit(methods, includeJniOnLoad);
    }
}
