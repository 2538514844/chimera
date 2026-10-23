package fixtures;

import dev.chimera.annotations.ChimeraProtected;

public final class Lic {
    private Lic() {
    }

    public static String label() {
        return "fixture-secret";
    }

    @ChimeraProtected
    public static boolean check(String hwid) {
        return hwid != null && hwid.startsWith("OK-") && hwid.length() == 5;
    }

    @ChimeraProtected
    public static int score(int a, int b) {
        return a * 3 + b * 11 + 42;
    }

    @ChimeraProtected
    public static int bonus(int value) {
        return value * 5 + 1;
    }

    @ChimeraProtected
    public static long coins(long value) {
        return value * 17L + 3L;
    }
}
