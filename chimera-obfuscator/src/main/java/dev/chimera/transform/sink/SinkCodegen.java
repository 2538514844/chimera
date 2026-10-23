package dev.chimera.transform.sink;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Deterministic C++/JNI text generation for the native sink.
 *
 * <p>Generated code fails closed at runtime: a missing class, a failed {@code RegisterNatives}
 * call or a failed {@code GetEnv} returns {@code JNI_ERR} instead of leaving the JVM with a
 * half-bound native table.</p>
 *
 * <p>Every generator re-sorts its input by {@code owner/name/descriptor} before emitting text, so
 * function order, manifest lines and {@code RegisterNatives} groups do not depend on the order in
 * which classes were visited (or on a caller passing an unsorted list).</p>
 */
final class SinkCodegen {

    private SinkCodegen() {
    }

    /** Canonical order shared by every generated artifact. */
    private static List<SinkSelectedMethod> canonical(List<SinkSelectedMethod> methods) {
        List<SinkSelectedMethod> sorted = new ArrayList<>(methods);
        sorted.sort(Comparator.comparing(SinkSelectedMethod::owner)
                .thenComparing(SinkSelectedMethod::name)
                .thenComparing(SinkSelectedMethod::descriptor));
        return sorted;
    }

    static String manifest(List<SinkSelectedMethod> methods) {
        List<SinkSelectedMethod> ordered = canonical(methods);
        StringBuilder sb = new StringBuilder(ordered.size() * 64);
        for (SinkSelectedMethod method : ordered) {
            sb.append(method.owner()).append('\t')
                    .append(method.name()).append('\t')
                    .append(method.descriptor()).append('\t');
            if (method.signature() != null) {
                sb.append(method.signature());
            }
            sb.append('\n');
        }
        return sb.toString();
    }

    /**
     * B plan: load-only class resolution.
     *
     * <p>JNI {@code FindClass} resolves <em>and links</em> the target class, so a sunk method dies at
     * the first lookup when the target class references an optional dependency that is not installed
     * (real case: {@code dev.idhammai.mod.modules.impl.client.BaritoneModule} -> {@code
     * NoClassDefFoundError: baritone/api/pathing/goals/Goal}). The Java bytecode path only
     * <em>loads</em> the same class during resolution, so it keeps running. Every generated lookup
     * therefore goes through {@code Class.forName(name, false, hostLoader)}: the failure moment, the
     * exception type and the message all match the Java semantics, and a class that is genuinely
     * missing still fails when the instruction that needs it executes.
     */
    private static final String RESOLVER = """
            #include <string>
            #include <cstdio>
            #include <cstdlib>

            // B plan: resolve/load only, never link. See NativeSinkTransformer docs.
            jclass chimera_sink_host_class = nullptr;

            static void chimera_sink_trace(const char* tag, const char* detail) {
                const char* path = getenv("CHIMERA_SINK_TRACE");
                if (path == nullptr || *path == 0) return;
                FILE* file = fopen(path, "a");
                if (file == nullptr) return;
                fprintf(file, "%s %s\\n", tag, detail == nullptr ? "" : detail);
                fclose(file);
            }

            static std::string chimera_sink_class_name(JNIEnv* env, jclass cls) {
                std::string out("<null>");
                if (cls == nullptr) return out;
                jclass clsClass = env->FindClass("java/lang/Class");
                if (clsClass == nullptr) { env->ExceptionClear(); return out; }
                jmethodID mid = env->GetMethodID(clsClass, "getName", "()Ljava/lang/String;");
                if (mid != nullptr) {
                    jstring name = (jstring)env->CallObjectMethod(cls, mid);
                    if (env->ExceptionCheck()) {
                        env->ExceptionClear();
                    } else if (name != nullptr) {
                        const char* chars = env->GetStringUTFChars(name, nullptr);
                        if (chars != nullptr) { out.assign(chars); env->ReleaseStringUTFChars(name, chars); }
                        env->DeleteLocalRef(name);
                    }
                }
                env->DeleteLocalRef(clsClass);
                return out;
            }

            static std::string chimera_sink_exception_text(JNIEnv* env) {
                std::string out("<none>");
                jthrowable pending = env->ExceptionOccurred();
                if (pending == nullptr) return out;
                env->ExceptionClear();
                jclass thr = env->FindClass("java/lang/Throwable");
                if (thr != nullptr) {
                    jmethodID mid = env->GetMethodID(thr, "toString", "()Ljava/lang/String;");
                    if (mid != nullptr) {
                        jstring text = (jstring)env->CallObjectMethod(pending, mid);
                        if (env->ExceptionCheck()) {
                            env->ExceptionClear();
                        } else if (text != nullptr) {
                            const char* chars = env->GetStringUTFChars(text, nullptr);
                            if (chars != nullptr) { out.assign(chars); env->ReleaseStringUTFChars(text, chars); }
                            env->DeleteLocalRef(text);
                        }
                    }
                    env->DeleteLocalRef(thr);
                }
                env->DeleteLocalRef(pending);
                return out;
            }

            static jobject chimera_sink_context_loader(JNIEnv* env) {
                jclass threadClass = env->FindClass("java/lang/Thread");
                if (threadClass == nullptr) { env->ExceptionClear(); return nullptr; }
                jmethodID current = env->GetStaticMethodID(threadClass, "currentThread", "()Ljava/lang/Thread;");
                jmethodID getCtx = env->GetMethodID(threadClass, "getContextClassLoader", "()Ljava/lang/ClassLoader;");
                jobject loader = nullptr;
                if (current != nullptr && getCtx != nullptr) {
                    jobject thread = env->CallStaticObjectMethod(threadClass, current);
                    if (thread != nullptr) {
                        loader = env->CallObjectMethod(thread, getCtx);
                        env->DeleteLocalRef(thread);
                    }
                }
                if (env->ExceptionCheck()) { env->ExceptionClear(); loader = nullptr; }
                env->DeleteLocalRef(threadClass);
                return loader;
            }

            static jobject chimera_sink_host_loader(JNIEnv* env) {
                static jobject cached = nullptr;
                if (cached != nullptr) return cached;
                if (chimera_sink_host_class == nullptr) {
                    static bool reported = false;
                    if (!reported) { reported = true; chimera_sink_trace("host_null", ""); }
                    return nullptr;
                }
                jclass clsClass = env->FindClass("java/lang/Class");
                if (clsClass == nullptr) { env->ExceptionClear(); return nullptr; }
                jmethodID mid = env->GetMethodID(clsClass, "getClassLoader", "()Ljava/lang/ClassLoader;");
                env->DeleteLocalRef(clsClass);
                if (mid == nullptr) { env->ExceptionClear(); return nullptr; }
                jobject local = env->CallObjectMethod(chimera_sink_host_class, mid);
                if (env->ExceptionCheck()) { env->ExceptionClear(); return nullptr; }
                if (local == nullptr) return nullptr;
                cached = env->NewGlobalRef(local);
                env->DeleteLocalRef(local);
                chimera_sink_trace("host_loader", chimera_sink_class_name(env, (jclass)env->GetObjectClass(local)).c_str());
                return cached;
            }

            static jclass chimera_sink_resolve(JNIEnv* env, const char* name) {
                static jclass clsClass = nullptr;
                static jmethodID midForName = nullptr;
                if (clsClass == nullptr) {
                    jclass local = env->FindClass("java/lang/Class");
                    if (local == nullptr) { env->ExceptionClear(); return nullptr; }
                    clsClass = (jclass)env->NewGlobalRef(local);
                    env->DeleteLocalRef(local);
                }
                if (midForName == nullptr) {
                    midForName = env->GetStaticMethodID(clsClass, "forName",
                            "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;");
                    if (midForName == nullptr) { env->ExceptionClear(); return nullptr; }
                }
                std::string dotted(name);
                for (size_t i = 0; i < dotted.size(); ++i) {
                    if (dotted[i] == '/') dotted[i] = '.';
                }
                jstring jname = env->NewStringUTF(dotted.c_str());
                if (jname == nullptr) { env->ExceptionClear(); return nullptr; }
                // 1) Thread context loader: Fabric installs the Knot loader as the context class
                //    loader of the game thread, so this is the loader the mod classes live in.
                jobject ctxLoader = chimera_sink_context_loader(env);
                jclass resolved = nullptr;
                if (ctxLoader != nullptr) {
                    resolved = (jclass)env->CallStaticObjectMethod(clsClass, midForName, jname, JNI_FALSE, ctxLoader);
                    if (!env->ExceptionCheck() && resolved != nullptr) {
                        env->DeleteLocalRef(ctxLoader);
                        env->DeleteLocalRef(jname);
                        return resolved;
                    }
                    std::string ctxError = chimera_sink_exception_text(env);
                    chimera_sink_trace("fail_ctx", (std::string(name) + " | " + ctxError).c_str());
                }
                // 2) Loader of the registered host class (set by RegisterNatives when that worked).
                resolved = (jclass)env->CallStaticObjectMethod(clsClass, midForName, jname, JNI_FALSE,
                        chimera_sink_host_loader(env));
                if (!env->ExceptionCheck() && resolved != nullptr) {
                    if (ctxLoader != nullptr) env->DeleteLocalRef(ctxLoader);
                    env->DeleteLocalRef(jname);
                    return resolved;
                }
                std::string hostError = chimera_sink_exception_text(env);
                chimera_sink_trace("fail_host", (std::string(name) + " | " + hostError).c_str());
                // 3) Null loader = bootstrap: JDK types only.
                resolved = (jclass)env->CallStaticObjectMethod(clsClass, midForName, jname, JNI_FALSE, nullptr);
                if (ctxLoader != nullptr) env->DeleteLocalRef(ctxLoader);
                if (!env->ExceptionCheck() && resolved != nullptr) {
                    env->DeleteLocalRef(jname);
                    return resolved;
                }
                std::string bootError = chimera_sink_exception_text(env);
                chimera_sink_trace("fail_boot", (std::string(name) + " | " + bootError).c_str());
                env->DeleteLocalRef(jname);
                jclass clsNcdfe = env->FindClass("java/lang/NoClassDefFoundError");
                if (clsNcdfe == nullptr) { env->ExceptionClear(); return nullptr; }
                env->ThrowNew(clsNcdfe, name);
                env->DeleteLocalRef(clsNcdfe);
                return nullptr;
            }

            """;

    static String unit(List<SinkSelectedMethod> methods, boolean includeJniOnLoad) {
        List<SinkSelectedMethod> ordered = canonical(methods);
        StringBuilder sb = new StringBuilder(16384);
        sb.append("// generated by dev.chimera.transform.sink.NativeSinkTransformer\n");
        sb.append("#include <jni.h>\n");
        sb.append("#include <cstdint>\n");
        sb.append("#include <cstring>\n");
        sb.append("#include <cmath>\n\n");
        if (ordered.isEmpty()) {
            sb.append("// no sink methods were selected.\n");
            return sb.toString();
        }
        sb.append(RESOLVER);
        for (SinkSelectedMethod method : ordered) {
            sb.append(method.cppSource());
            if (!method.cppSource().endsWith("\n")) {
                sb.append('\n');
            }
            sb.append('\n');
        }
        sb.append(registration(ordered, includeJniOnLoad));
        return sb.toString();
    }

    static String registration(List<SinkSelectedMethod> methods, boolean includeJniOnLoad) {
        List<SinkSelectedMethod> ordered = canonical(methods);
        StringBuilder sb = new StringBuilder(4096);
        sb.append("// chimera NativeSinkTransformer: generated RegisterNatives wiring.\n");
        sb.append("#include <jni.h>\n");
        sb.append("#include <cstdio>\n\n");
        sb.append("// B plan: the first host class we register on provides the class loader used by\n");
        sb.append("// chimera_sink_resolve() (defined in the generated unit).\n");
        sb.append("extern jclass chimera_sink_host_class;\n\n");
        if (ordered.isEmpty()) {
            sb.append("// no sink methods were selected; nothing to register.\n");
            return sb.toString();
        }
        // C-3: registration is the authoritative binding path, not a best-effort extra. Each
        // group reports its own outcome so the Java side can tell "every method bound" from
        // "nothing bound" and fail closed on the latter.
        if (includeJniOnLoad) {
            sb.append("// Build with -DCHIMERA_SINK_EXTERNAL_JNI_ONLOAD and call\n")
                    .append("// chimera_sink_register_all_with_host(env, hostClass) from your own\n")
                    .append("// JNI_OnLoad when this unit is linked into a library that already\n")
                    .append("// exports JNI_OnLoad.\n");
        }

        Map<String, List<SinkSelectedMethod>> byOwner = new LinkedHashMap<>();
        for (SinkSelectedMethod method : ordered) {
            byOwner.computeIfAbsent(method.owner(), key -> new ArrayList<>()).add(method);
        }

        int group = 0;
        for (Map.Entry<String, List<SinkSelectedMethod>> entry : byOwner.entrySet()) {
            List<SinkSelectedMethod> groupMethods = entry.getValue();
            String suffix = Integer.toString(group);
            String owner = cString(entry.getKey());
            sb.append("\n// ").append(entry.getKey()).append('\n');
            sb.append("static const JNINativeMethod chimera_sink_methods_").append(suffix).append("[] = {\n");
            for (SinkSelectedMethod method : groupMethods) {
                sb.append("    { const_cast<char*>(\"").append(cString(method.name()))
                        .append("\"), const_cast<char*>(\"").append(cString(method.descriptor()))
                        .append("\"), reinterpret_cast<void*>(&").append(method.symbol()).append(") },\n");
            }
            sb.append("};\n\n");
            sb.append("static jint chimera_sink_register_").append(suffix).append("(JNIEnv* env) {\n");
            sb.append("    // C-3: load-only resolution. env->FindClass would link the host class and\n");
            sb.append("    // fail on optional dependencies the Java path never touches.\n");
            sb.append("    jclass cls = chimera_sink_resolve(env, \"").append(owner).append("\");\n");
            sb.append("    if (cls == nullptr) {\n");
            sb.append("        env->ExceptionClear();\n");
            sb.append("        chimera_sink_trace(\"reg_unresolved\", \"").append(owner).append("\");\n");
            sb.append("        return 1;\n");
            sb.append("    }\n");
            sb.append("    jint rc = env->RegisterNatives(cls, chimera_sink_methods_").append(suffix)
                    .append(",\n            static_cast<jint>(sizeof(chimera_sink_methods_").append(suffix)
                    .append(") / sizeof(chimera_sink_methods_").append(suffix).append("[0])));\n");
            sb.append("    if (rc != JNI_OK) {\n");
            sb.append("        env->ExceptionClear();\n");
            sb.append("        chimera_sink_trace(\"reg_link_fail\", \"").append(owner).append("\");\n");
            sb.append("        env->DeleteLocalRef(cls);\n");
            sb.append("        return 1;\n");
            sb.append("    }\n");
            sb.append("    if (chimera_sink_host_class == nullptr) {\n");
            sb.append("        chimera_sink_host_class = (jclass)env->NewGlobalRef(cls);\n");
            sb.append("        if (chimera_sink_host_class != nullptr) {\n");
            sb.append("            chimera_sink_host_loader(env);\n");
            sb.append("        }\n");
            sb.append("    }\n");
            sb.append("    env->DeleteLocalRef(cls);\n");
            sb.append("    return 0;\n");
            sb.append("}\n");
            group++;
        }

        sb.append("\n// Returns 0 when every group bound, a positive count of failed groups, or a\n");
        sb.append("// negative number when every group failed (the Java side fails closed on that).\n");
        sb.append("extern \"C\" JNIEXPORT jint JNICALL chimera_sink_register_all(JNIEnv* env) {\n");
        sb.append("    if (env == nullptr) {\n");
        sb.append("        return -1;\n");
        sb.append("    }\n");
        sb.append("    jint failed = 0;\n");
        for (int i = 0; i < group; i++) {
            sb.append("    failed += chimera_sink_register_").append(i).append("(env);\n");
        }
        sb.append("    if (failed == 0) {\n");
        sb.append("        chimera_sink_trace(\"reg_ok\", \"");
        sb.append(Integer.toString(group)).append(" groups\");\n");
        sb.append("        return 0;\n");
        sb.append("    }\n");
        sb.append("    char detail[64];\n");
        sb.append("    snprintf(detail, sizeof(detail), \"failed=%d of ").append(Integer.toString(group)).append("\", (int)failed);\n");
        sb.append("    chimera_sink_trace(\"reg_failed\", detail);\n");
        sb.append("    return failed == ").append(Integer.toString(group)).append(" ? -(jint)failed : failed;\n");
        sb.append("}\n");

        sb.append("\n// C-3: host-aware entry. The class that triggers registration lives in the mod\n");
        sb.append("// class loader, so it is both the resolution host and the loader fallback.\n");
        sb.append("extern \"C\" JNIEXPORT jint JNICALL chimera_sink_register_all_with_host(\n");
        sb.append("        JNIEnv* env, jclass host) {\n");
        sb.append("    if (env == nullptr) {\n");
        sb.append("        return -1;\n");
        sb.append("    }\n");
        sb.append("    if (host != nullptr && chimera_sink_host_class == nullptr) {\n");
        sb.append("        chimera_sink_host_class = (jclass)env->NewGlobalRef(host);\n");
        sb.append("    }\n");
        sb.append("    return chimera_sink_register_all(env);\n");
        sb.append("}\n");

        if (includeJniOnLoad) {
            sb.append("\n#ifndef CHIMERA_SINK_EXTERNAL_JNI_ONLOAD\n");
            sb.append("extern \"C\" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {\n");
            sb.append("    (void)reserved;\n");
            sb.append("    if (vm == nullptr) {\n");
            sb.append("        return JNI_ERR;\n");
            sb.append("    }\n");
            sb.append("    JNIEnv* env = nullptr;\n");
            sb.append("    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_8) != JNI_OK\n");
            sb.append("            || env == nullptr) {\n");
            sb.append("        return JNI_ERR;\n");
            sb.append("    }\n");
            sb.append("    if (chimera_sink_register_all(env) < 0) {\n");
            sb.append("        return JNI_ERR;\n");
            sb.append("    }\n");
            sb.append("    return JNI_VERSION_1_8;\n");
            sb.append("}\n");
            sb.append("#endif  // CHIMERA_SINK_EXTERNAL_JNI_ONLOAD\n");
        }
        return sb.toString();
    }

    /**
     * C-3: names must be emitted as modified UTF-8 bytes. The old one-byte-per-char escaping
     * broke every invisible-renamed owner/member name (and crashed the VM inside
     * {@code jni_RegisterNatives} while interning the malformed symbol).
     */
    private static String cString(String value) {
        return dev.chimera.core.CppLiteral.escape(value);
    }
}
