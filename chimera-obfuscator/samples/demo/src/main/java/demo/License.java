package demo;

import dev.chimera.annotations.ChimeraProtected;

public final class License {
    private License() {
    }

    public static String label() {
        return "chimera-demo-secret";
    }

    @ChimeraProtected
    public static boolean check(String hwid) {
        if (hwid == null || !hwid.startsWith("HWID-")) return false;
        int h = hwid.hashCode() & 0x7fffffff;
        return h % 7 == 0;
    }

    @ChimeraProtected
    public static int score(int a, int b) {
        return a * 3 + b * 11 + 42;
    }
}
