package dev.chimera.transform.mixinsupport;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal, dependency-free JSON reader and writer for mixin metadata.
 *
 * <p>The reader is deliberately lenient because Sponge Mixin parses its configs with Gson in
 * lenient mode: line and block comments, single-quoted strings, unquoted object
 * keys and trailing commas are accepted. Duplicate object keys are rejected because rewriting a
 * config with duplicated {@code mixins}/{@code package} fields would silently drop one of them.
 * The writer always emits strict JSON, so a config that was merely "Gson-readable" becomes
 * valid JSON after a rewrite. Values that are not rewritten are copied byte-for-byte as
 * serialized values (numbers keep their integer/fractional nature, unknown fields are kept).</p>
 */
final class Json {

    private Json() {
    }

    /** Parses a single JSON document; trailing content is rejected. */
    static Object parse(String text) {
        if (text == null) {
            throw new ParseException("null JSON input");
        }
        return new Parser(text).parseDocument();
    }

    /** Serializes a value tree produced by {@link #parse(String)} (or an equivalent structure). */
    static String write(Object value) {
        StringBuilder out = new StringBuilder(256);
        writeValue(out, value);
        return out.toString();
    }

    /** Thrown for malformed JSON; callers wrap it with the offending jar entry name. */
    static final class ParseException extends RuntimeException {

        private static final long serialVersionUID = 1L;

        ParseException(String message) {
            super(message);
        }
    }

    private static void writeValue(StringBuilder out, Object value) {
        if (value == null) {
            out.append("null");
        } else if (value instanceof String string) {
            writeString(out, string);
        } else if (value instanceof Boolean bool) {
            out.append(bool.booleanValue());
        } else if (value instanceof Double || value instanceof Float) {
            double number = ((Number) value).doubleValue();
            if (Double.isNaN(number) || Double.isInfinite(number)) {
                throw new IllegalArgumentException("non-finite number cannot be represented as JSON");
            }
            out.append(number);
        } else if (value instanceof Number number) {
            out.append(number.toString());
        } else if (value instanceof Map<?, ?> map) {
            out.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!(entry.getKey() instanceof String key)) {
                    throw new IllegalArgumentException("JSON object keys must be strings");
                }
                if (!first) {
                    out.append(',');
                }
                first = false;
                writeString(out, key);
                out.append(':');
                writeValue(out, entry.getValue());
            }
            out.append('}');
        } else if (value instanceof Iterable<?> iterable) {
            out.append('[');
            boolean first = true;
            for (Object item : iterable) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                writeValue(out, item);
            }
            out.append(']');
        } else if (value instanceof Object[] array) {
            out.append('[');
            for (int i = 0; i < array.length; i++) {
                if (i > 0) {
                    out.append(',');
                }
                writeValue(out, array[i]);
            }
            out.append(']');
        } else {
            throw new IllegalArgumentException(
                    "unsupported JSON value type: " + value.getClass().getName());
        }
    }

    private static void writeString(StringBuilder out, String value) {
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        String hex = Integer.toHexString(c);
                        out.append("\\u");
                        for (int pad = hex.length(); pad < 4; pad++) {
                            out.append('0');
                        }
                        out.append(hex);
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }

    private static final class Parser {

        private static final int MAX_DEPTH = 256;
        private final String text;
        private int pos;
        private int depth;

        Parser(String text) {
            this.text = text;
        }

        Object parseDocument() {
            if (!text.isEmpty() && text.charAt(0) == '\uFEFF') {
                pos = 1;
            }
            skipWhitespace();
            if (pos >= text.length()) {
                throw error("empty document");
            }
            Object value = parseValue();
            skipWhitespace();
            if (pos != text.length()) {
                throw error("trailing characters");
            }
            return value;
        }

        private Object parseValue() {
            if (pos >= text.length()) {
                throw error("unexpected end of input");
            }
            char c = text.charAt(pos);
            return switch (c) {
                case '{' -> parseObject();
                case '[' -> parseArray();
                case '"', '\'' -> parseString(c);
                default -> parseBareValue(c);
            };
        }

        private Object parseBareValue(char c) {
            if (c == '-' || (c >= '0' && c <= '9')) {
                return parseNumber();
            }
            if (consumeLiteral("true")) {
                return Boolean.TRUE;
            }
            if (consumeLiteral("false")) {
                return Boolean.FALSE;
            }
            if (consumeLiteral("null")) {
                return null;
            }
            throw error("unexpected character '" + c + "'");
        }

        private Map<String, Object> parseObject() {
            enter();
            pos++;
            Map<String, Object> object = new LinkedHashMap<>();
            skipWhitespace();
            if (peek() == '}') {
                pos++;
                depth--;
                return object;
            }
            while (true) {
                skipWhitespace();
                if (peek() == '}') {
                    pos++;
                    depth--;
                    return object;
                }
                String key = parseKey();
                skipWhitespace();
                expect(':');
                skipWhitespace();
                Object value = parseValue();
                if (object.containsKey(key)) {
                    throw error("duplicate key \"" + key + "\"");
                }
                object.put(key, value);
                skipWhitespace();
                char c = peek();
                if (c == ',') {
                    pos++;
                    continue;
                }
                if (c == '}') {
                    pos++;
                    depth--;
                    return object;
                }
                throw error("expected ',' or '}' but found '" + c + "'");
            }
        }

        private List<Object> parseArray() {
            enter();
            pos++;
            List<Object> array = new ArrayList<>();
            skipWhitespace();
            if (peek() == ']') {
                pos++;
                depth--;
                return array;
            }
            while (true) {
                skipWhitespace();
                if (peek() == ']') {
                    pos++;
                    depth--;
                    return array;
                }
                array.add(parseValue());
                skipWhitespace();
                char c = peek();
                if (c == ',') {
                    pos++;
                    continue;
                }
                if (c == ']') {
                    pos++;
                    depth--;
                    return array;
                }
                throw error("expected ',' or ']' but found '" + c + "'");
            }
        }

        private String parseKey() {
            char c = peek();
            if (c == '"' || c == '\'') {
                return parseString(c);
            }
            int start = pos;
            while (pos < text.length()) {
                char ch = text.charAt(pos);
                if (ch == ':' || ch == '{' || ch == '}' || ch == '[' || ch == ','
                        || Character.isWhitespace(ch)) {
                    break;
                }
                pos++;
            }
            if (pos == start) {
                throw error("empty object key");
            }
            return text.substring(start, pos);
        }

        private String parseString(char quote) {
            pos++;
            StringBuilder out = new StringBuilder();
            while (pos < text.length()) {
                char c = text.charAt(pos++);
                if (c == quote) {
                    return out.toString();
                }
                if (c == '\\') {
                    if (pos >= text.length()) {
                        throw error("unterminated escape sequence");
                    }
                    char escaped = text.charAt(pos++);
                    switch (escaped) {
                        case '"' -> out.append('"');
                        case '\'' -> out.append('\'');
                        case '\\' -> out.append('\\');
                        case '/' -> out.append('/');
                        case 'b' -> out.append('\b');
                        case 'f' -> out.append('\f');
                        case 'n' -> out.append('\n');
                        case 'r' -> out.append('\r');
                        case 't' -> out.append('\t');
                        case 'u' -> out.append(parseUnicodeEscape());
                        default -> throw error("invalid escape sequence \\" + escaped);
                    }
                    continue;
                }
                if (c < 0x20) {
                    throw error("unescaped control character in string");
                }
                out.append(c);
            }
            throw error("unterminated string");
        }

        private char parseUnicodeEscape() {
            if (pos + 4 > text.length()) {
                throw error("truncated unicode escape");
            }
            int value = 0;
            for (int i = 0; i < 4; i++) {
                int digit = Character.digit(text.charAt(pos++), 16);
                if (digit < 0) {
                    throw error("invalid unicode escape");
                }
                value = (value << 4) | digit;
            }
            return (char) value;
        }

        private Object parseNumber() {
            int start = pos;
            if (peek() == '-') {
                pos++;
            }
            if (pos >= text.length() || !isDigit(text.charAt(pos))) {
                throw error("invalid number");
            }
            while (pos < text.length() && isDigit(text.charAt(pos))) {
                pos++;
            }
            boolean floating = false;
            if (pos < text.length() && text.charAt(pos) == '.') {
                floating = true;
                pos++;
                if (pos >= text.length() || !isDigit(text.charAt(pos))) {
                    throw error("invalid number");
                }
                while (pos < text.length() && isDigit(text.charAt(pos))) {
                    pos++;
                }
            }
            if (pos < text.length() && (text.charAt(pos) == 'e' || text.charAt(pos) == 'E')) {
                floating = true;
                pos++;
                if (pos < text.length() && (text.charAt(pos) == '+' || text.charAt(pos) == '-')) {
                    pos++;
                }
                if (pos >= text.length() || !isDigit(text.charAt(pos))) {
                    throw error("invalid number");
                }
                while (pos < text.length() && isDigit(text.charAt(pos))) {
                    pos++;
                }
            }
            String literal = text.substring(start, pos);
            if (!floating) {
                try {
                    return Long.parseLong(literal);
                } catch (NumberFormatException ignored) {
                    // integral literal outside the long range: fall through to double
                }
            }
            double value = Double.parseDouble(literal);
            if (Double.isInfinite(value) || Double.isNaN(value)) {
                throw error("number out of range");
            }
            return value;
        }

        private void skipWhitespace() {
            while (pos < text.length()) {
                char c = text.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f') {
                    pos++;
                    continue;
                }
                if (c == '/' && pos + 1 < text.length()) {
                    char next = text.charAt(pos + 1);
                    if (next == '/') {
                        pos += 2;
                        while (pos < text.length() && text.charAt(pos) != '\n'
                                && text.charAt(pos) != '\r') {
                            pos++;
                        }
                        continue;
                    }
                    if (next == '*') {
                        int end = text.indexOf("*/", pos + 2);
                        if (end < 0) {
                            throw error("unterminated comment");
                        }
                        pos = end + 2;
                        continue;
                    }
                }
                break;
            }
        }

        private char peek() {
            if (pos >= text.length()) {
                throw error("unexpected end of input");
            }
            return text.charAt(pos);
        }

        private void expect(char expected) {
            if (peek() != expected) {
                throw error("expected '" + expected + "'");
            }
            pos++;
        }

        private boolean consumeLiteral(String literal) {
            if (!text.startsWith(literal, pos)) {
                return false;
            }
            pos += literal.length();
            return true;
        }

        private void enter() {
            if (++depth > MAX_DEPTH) {
                throw error("maximum nesting depth exceeded");
            }
        }

        private static boolean isDigit(char c) {
            return c >= '0' && c <= '9';
        }

        private ParseException error(String message) {
            int line = 1;
            int column = 1;
            int limit = Math.min(pos, text.length());
            for (int i = 0; i < limit; i++) {
                if (text.charAt(i) == '\n') {
                    line++;
                    column = 1;
                } else {
                    column++;
                }
            }
            return new ParseException(message + " at line " + line + ", column " + column);
        }
    }
}
