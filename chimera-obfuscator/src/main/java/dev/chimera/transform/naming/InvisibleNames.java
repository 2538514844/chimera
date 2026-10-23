package dev.chimera.transform.naming;

import java.util.Set;

/**
 * M13: invisible-character naming primitives.
 *
 * <p>Hachimi appends invisible code points to member names and hidden-class entry names. This
 * class centralises the code-point set and the deterministic suffix encoding so the transformer,
 * the tests and any future report can share one definition:</p>
 *
 * <ul>
 *   <li>{@link #LTR} (U+200E), {@link #RTL} (U+200F), {@link #WJ} (U+2060) are the invisible
 *       code points used by the suffix;</li>
 *   <li>every suffix starts with {@link #LTR} and then encodes a unique id in base 3 using the
 *       three code points as digits, so suffixes are a "combination" of all three alphabets and
 *       are unique per id;</li>
 *   <li>{@link #NUL} is the optional experimental class-name prefix (off by default) observed in
 *       the Hachimi sample ({@code \0eK\u200e}).</li>
 * </ul>
 *
 * <p>None of these code points is an identifier character for Java, so source-looking output
 * ("a", "a\u200e") stays visually identical while the JVM treats the names as distinct.</p>
 */
public final class InvisibleNames {

    /** LEFT-TO-RIGHT MARK, U+200E. */
    public static final char LTR = '\u200E';
    /** RIGHT-TO-LEFT MARK, U+200F. */
    public static final char RTL = '\u200F';
    /** WORD JOINER, U+2060. */
    public static final char WJ = '\u2060';
    /** Experimental NUL class-name prefix (Hachimi's {@code \0} entry names). */
    public static final char NUL = 0;

    /** The three code points that may appear in a suffix. */
    public static final Set<Character> TARGET_CODE_POINTS = Set.of(LTR, RTL, WJ);

    private static final char[] DIGITS = {LTR, RTL, WJ};

    private InvisibleNames() {
    }

    /**
     * Deterministic invisible suffix for the given id: {@code U+200E} followed by the id in base 3
     * (each digit is {@link #LTR}, {@link #RTL} or {@link #WJ}). Id {@code 0} yields
     * {@code U+200E U+200E} so every suffix has at least two invisible characters.
     *
     * @param id non-negative unique id inside the renamed element's scope
     * @return suffix consisting only of {@link #TARGET_CODE_POINTS}
     */
    public static String suffix(int id) {
        if (id < 0) {
            throw new IllegalArgumentException("id must be >= 0: " + id);
        }
        StringBuilder sb = new StringBuilder(4);
        sb.append(LTR);
        int value = id;
        do {
            sb.append(DIGITS[value % DIGITS.length]);
            value /= DIGITS.length;
        } while (value > 0);
        return sb.toString();
    }

    /** True when {@code name} contains at least one of {@link #TARGET_CODE_POINTS}. */
    public static boolean containsInvisible(String name) {
        if (name == null) {
            return false;
        }
        for (int i = 0; i < name.length(); i++) {
            if (TARGET_CODE_POINTS.contains(name.charAt(i))) {
                return true;
            }
        }
        return false;
    }

    /** True when {@code name} already carries invisible naming (re-processed output). */
    public static boolean alreadyRenamed(String name) {
        return name != null && (containsInvisible(name) || name.indexOf(NUL) >= 0);
    }

    /** Binary name ({@code a.b.C}) of an internal name ({@code a/b/C}). */
    public static String binaryName(String internalName) {
        return internalName.replace('/', '.');
    }

    /** Simple (unqualified) class name of an internal name. */
    public static String simpleName(String internalName) {
        int slash = internalName.lastIndexOf('/');
        return slash < 0 ? internalName : internalName.substring(slash + 1);
    }

    /** Package prefix of an internal name, including the trailing slash (may be empty). */
    public static String packagePrefix(String internalName) {
        int slash = internalName.lastIndexOf('/');
        return slash < 0 ? "" : internalName.substring(0, slash + 1);
    }
}
