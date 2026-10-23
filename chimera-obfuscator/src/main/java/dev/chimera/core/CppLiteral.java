package dev.chimera.core;

import java.util.Locale;

/**
 * Escapes a Java string into a C/C++ string literal body that carries <em>modified UTF-8</em> bytes.
 *
 * <p>This matters for the native sink: after {@code --invisible-naming} every class and member name
 * contains invisible BMP characters (U+200E/U+200F/U+2060). The JNI name tables and
 * {@code Class.forName} both expect modified UTF-8, so the generated literal must contain the
 * UTF-8 byte sequence of each code point, not the low byte of the Java {@code char}. Emitting one
 * byte per {@code char} produced literals like {@code "eh\20016..."}, which made
 * {@code RegisterNatives} fail for every renamed member and could crash the VM inside
 * {@code jni_RegisterNatives} while interning the malformed symbol.</p>
 */
public final class CppLiteral {

    private CppLiteral() {
    }

    /** Returns the escaped body of a C++ string literal (without the surrounding quotes). */
    public static String escape(String value) {
        StringBuilder sb = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '"' -> sb.append("\\\"");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c >= 32 && c < 127) {
                        sb.append(c);
                    } else if (c == 0) {
                        // modified UTF-8 never emits a raw NUL: it is the two-byte C0 80 sequence.
                        octal(sb, 0xC0);
                        octal(sb, 0x80);
                    } else if (c < 0x80) {
                        octal(sb, c);
                    } else if (c < 0x800) {
                        octal(sb, 0xC0 | (c >> 6));
                        octal(sb, 0x80 | (c & 0x3F));
                    } else {
                        // BMP char, or one half of a surrogate pair: CESU-8 == modified UTF-8.
                        octal(sb, 0xE0 | (c >> 12));
                        octal(sb, 0x80 | ((c >> 6) & 0x3F));
                        octal(sb, 0x80 | (c & 0x3F));
                    }
                }
            }
        }
        return sb.toString();
    }

    private static void octal(StringBuilder sb, int value) {
        sb.append(String.format(Locale.ROOT, "\\%03o", value & 0xFF));
    }
}
