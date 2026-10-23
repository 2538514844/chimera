package dev.chimera.core;

import org.objectweb.asm.Type;

/**
 * Emits compilable JNI artifacts for a {@link NativeTemplate}: a {@code .h} declaration and a
 * {@code .cpp} definition (transpiled body when supported, TODO stub otherwise).
 */
public final class NativeTemplateWriter {
    private NativeTemplateWriter() {
    }

    /** Header file: include guard via pragma once, JNI types, Java narrowing helpers, declaration. */
    public static String generateHeader(NativeTemplate t) {
        StringBuilder sb = new StringBuilder();
        sb.append("#pragma once\n");
        sb.append("#include <jni.h>\n\n");
        sb.append("// UB-free helpers for Java semantics on C++ (see docs/M4-JNIC.md).\n");
        sb.append("typedef unsigned int chimera_u32;\n");
        sb.append("typedef unsigned long long chimera_u64;\n\n");
        sb.append("// Java int/long division & remainder: b==0 would throw ArithmeticException in Java;\n");
        sb.append("// the native version returns 0 instead (documented limitation) and guards MIN/-1.\n");
        sb.append("static inline jint chimera_idiv(jint a, jint b) {\n");
        sb.append("    if (b == 0) return 0;\n");
        sb.append("    if (a == (-2147483647 - 1) && b == -1) return (-2147483647 - 1);\n");
        sb.append("    return a / b;\n");
        sb.append("}\n");
        sb.append("static inline jint chimera_irem(jint a, jint b) {\n");
        sb.append("    if (b == 0) return 0;\n");
        sb.append("    if (a == (-2147483647 - 1) && b == -1) return 0;\n");
        sb.append("    return a % b;\n");
        sb.append("}\n");
        sb.append("static inline jlong chimera_ldiv(jlong a, jlong b) {\n");
        sb.append("    if (b == 0) return 0;\n");
        sb.append("    if (a == (-9223372036854775807LL - 1) && b == -1) return (-9223372036854775807LL - 1);\n");
        sb.append("    return a / b;\n");
        sb.append("}\n");
        sb.append("static inline jlong chimera_lrem(jlong a, jlong b) {\n");
        sb.append("    if (b == 0) return 0;\n");
        sb.append("    if (a == (-9223372036854775807LL - 1) && b == -1) return 0;\n");
        sb.append("    return a % b;\n");
        sb.append("}\n\n");
        sb.append("// Arithmetic shift right without implementation-defined signed shifts.\n");
        sb.append("static inline jint chimera_isar(jint v, jint n) {\n");
        sb.append("    n &= 31;\n");
        sb.append("    return v >= 0 ? (v >> n) : ~(~v >> n);\n");
        sb.append("}\n");
        sb.append("static inline jlong chimera_lsar(jlong v, jint n) {\n");
        sb.append("    n &= 63;\n");
        sb.append("    return v >= 0 ? (v >> n) : ~(~v >> n);\n");
        sb.append("}\n\n");
        sb.append("// Exact Java narrowing semantics (saturating, NaN -> 0) for d2i / d2l.\n");
        sb.append("static inline jint chimera_d2i(jdouble v) {\n");
        sb.append("    if (v != v) return 0;\n");
        sb.append("    if (v >= 2147483647.0) return 2147483647;\n");
        sb.append("    if (v <= -2147483648.0) return -2147483648;\n");
        sb.append("    return (jint) v;\n");
        sb.append("}\n\n");
        sb.append("static inline jlong chimera_d2l(jdouble v) {\n");
        sb.append("    if (v != v) return 0;\n");
        sb.append("    if (v >= 9223372036854775807.0) return 9223372036854775807LL;\n");
        sb.append("    if (v <= -9223372036854775808.0) return (-9223372036854775807LL - 1);\n");
        sb.append("    return (jlong) v;\n");
        sb.append("}\n\n");
        sb.append("// Java dcmpg/dcmpl: NaN orders high for dcmpg, low for dcmpl.\n");
        sb.append("static inline jint chimera_dcmpg(jdouble a, jdouble b) {\n");
        sb.append("    if (a < b) return -1;\n");
        sb.append("    if (a > b) return 1;\n");
        sb.append("    if (a == b) return 0;\n");
        sb.append("    return 1;\n");
        sb.append("}\n");
        sb.append("static inline jint chimera_dcmpl(jdouble a, jdouble b) {\n");
        sb.append("    if (a < b) return -1;\n");
        sb.append("    if (a > b) return 1;\n");
        sb.append("    if (a == b) return 0;\n");
        sb.append("    return -1;\n");
        sb.append("}\n\n");
        sb.append(t.headerDecl() != null
                ? t.headerDecl()
                : headerDeclaration(t.classInternalName(), t.methodName(), t.descriptor(), t.isStatic()));
        sb.append('\n');
        return sb.toString();
    }

    /** Source file: includes the matching header and defines the JNI entry point. */
    public static String generateSource(NativeTemplate t) {
        String base = fileBase(t);
        StringBuilder sb = new StringBuilder();
        sb.append("#include \"").append(base).append(".h\"\n");
        sb.append("#include <cmath>\n\n");
        sb.append(definitionFor(t)).append(" {\n");
        if (t.supported() && t.cppBody() != null && !t.cppBody().isBlank()) {
            sb.append(t.cppBody());
            if (!t.cppBody().endsWith("\n")) sb.append('\n');
        } else {
            sb.append("    // TODO: implement ").append(t.methodName()).append(t.descriptor()).append('\n');
            String ret = defaultReturn(t.descriptor());
            if (!ret.isEmpty()) sb.append("    ").append(ret).append('\n');
        }
        sb.append("}\n");
        return sb.toString();
    }

    /** Legacy entry point kept for callers that only know about the old template format. */
    public static String generate(NativeTemplate t) {
        return generateSource(t);
    }

    /** File stem shared by {@code <Class>_<method>.h} and {@code .cpp}. */
    public static String fileBase(NativeTemplate t) {
        String base = t.classInternalName().replace('/', '_') + "_" + t.methodName();
        // Overloaded natives use the JNI long symbol; give their .h/.cpp a stable suffix so the
        // files do not overwrite each other.
        if (t.headerDecl() != null && t.headerDecl().contains("__")) {
            base += "_" + Integer.toHexString(t.descriptor().hashCode());
        }
        return base;
    }

    /** Full {@code extern "C"} declaration, terminated by a semicolon. */
    public static String headerDeclaration(String classInternalName, String methodName,
                                          String descriptor, boolean isStatic) {
        return headerDeclaration(classInternalName, methodName, descriptor, isStatic, false);
    }

    /**
     * Overload-aware declaration. The JVM first looks up the short JNI symbol and, for overloaded
     * native methods, the long symbol {@code Java_Class_method__<mangled descriptor>} (JVMS JNI
     * naming rules). The descriptor suffix is what makes {@code RegisterNatives} / automatic
     * lookup bind the exact overload; a custom {@code _int}/{@code _double} suffix would break
     * automatic lookup.
     */
    public static String headerDeclaration(String classInternalName, String methodName,
                                          String descriptor, boolean isStatic, boolean overloaded) {
        StringBuilder sb = new StringBuilder();
        sb.append("extern \"C\" JNIEXPORT ").append(jniType(Type.getReturnType(descriptor)))
          .append(" JNICALL ").append(jniName(classInternalName, methodName, descriptor, overloaded))
          .append("(JNIEnv* env, ").append(isStatic ? "jclass clazz" : "jobject self");
        Type[] args = Type.getArgumentTypes(descriptor);
        for (int i = 0; i < args.length; i++) {
            sb.append(", ").append(jniType(args[i])).append(" a").append(i);
        }
        sb.append(");");
        return sb.toString();
    }

    private static String definitionFor(NativeTemplate t) {
        String decl = t.headerDecl() != null
                ? t.headerDecl()
                : headerDeclaration(t.classInternalName(), t.methodName(), t.descriptor(), t.isStatic());
        return decl.endsWith(";") ? decl.substring(0, decl.length() - 1) : decl;
    }

    /**
     * JNI symbol name for a native method (JVMS/JNI spec mangling):
     * '/' and '.' become '_', '_' becomes "_1", ';' "_2", '[' "_3", '$' and other
     * non-alphanumerics become "_0xxxx" (four lower-case hex digits).
     *
     * <p>The historic implementation re-escaped the already-substituted package separators
     * ("demo_Hwid" -> "demo_5f_Hwid"), so the compiled library exported a symbol the JVM never
     * looks up and every call failed with UnsatisfiedLinkError. Fixed here; the file stem keeps
     * the old {@code <Class>_<method>} naming so existing artifact paths stay stable.</p>
     */
    public static String jniName(String classInternalName, String methodName) {
        return "Java_" + mangle(classInternalName) + "_" + mangle(methodName);
    }

    public static String jniName(String classInternalName, String methodName,
                          String descriptor, boolean overloaded) {
        if (!overloaded || descriptor == null) {
            return jniName(classInternalName, methodName);
        }
        return "Java_" + mangle(classInternalName) + "_" + mangle(methodName)
                + "__" + mangleDescriptor(descriptor);
    }

    /**
     * JVMS JNI long-name descriptor mangling: the long name uses the parameter types only
     * (no parentheses, no return type). Example: {@code clamp(DDD)D -> "DDD"}.
     */
    private static String mangleDescriptor(String descriptor) {
        StringBuilder sb = new StringBuilder();
        for (Type arg : Type.getArgumentTypes(descriptor)) {
            String d = arg.getDescriptor();
            for (int i = 0; i < d.length(); i++) {
                char c = d.charAt(i);
                if (c == '/' || c == '.') sb.append('_');
                else if (c == '_') sb.append("_1");
                else if (c == ';') sb.append("_2");
                else if (c == '[') sb.append("_3");
                else sb.append(c);
            }
        }
        return sb.toString();
    }

    private static String mangle(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '/' || c == '.') sb.append('_');
            else if (c == '_') sb.append("_1");
            else if (c == ';') sb.append("_2");
            else if (c == '[') sb.append("_3");
            else if (Character.isLetterOrDigit(c) && c < 128) sb.append(c);
            else sb.append("_0").append(String.format("%04x", (int) c));
        }
        return sb.toString();
    }

    private static String jniType(Type t) {
        return switch (t.getSort()) {
            case Type.VOID -> "void";
            case Type.BOOLEAN -> "jboolean";
            case Type.BYTE -> "jbyte";
            case Type.CHAR -> "jchar";
            case Type.SHORT -> "jshort";
            case Type.INT -> "jint";
            case Type.LONG -> "jlong";
            case Type.FLOAT -> "jfloat";
            case Type.DOUBLE -> "jdouble";
            case Type.OBJECT -> {
                if (t.getInternalName().equals("java/lang/String")) yield "jstring";
                yield "jobject";
            }
            case Type.ARRAY -> switch (t.getElementType().getSort()) {
                case Type.BOOLEAN -> "jbooleanArray";
                case Type.BYTE -> "jbyteArray";
                case Type.CHAR -> "jcharArray";
                case Type.SHORT -> "jshortArray";
                case Type.INT -> "jintArray";
                case Type.LONG -> "jlongArray";
                case Type.FLOAT -> "jfloatArray";
                case Type.DOUBLE -> "jdoubleArray";
                default -> "jobjectArray";
            };
            default -> "jobject";
        };
    }

    private static String defaultReturn(String desc) {
        return switch (Type.getReturnType(desc).getSort()) {
            case Type.VOID -> "";
            case Type.BOOLEAN, Type.BYTE, Type.CHAR, Type.SHORT, Type.INT -> "return 0;";
            case Type.LONG -> "return 0L;";
            case Type.FLOAT -> "return 0.0f;";
            case Type.DOUBLE -> "return 0.0;";
            default -> "return nullptr;";
        };
    }
}
