package fixtures;

import dev.chimera.annotations.ChimeraEntangle;

public final class Entangled {
    private Entangled() {
    }

    @ChimeraEntangle
    public static int damage(int attack, int defense) {
        return attack * 7 - defense * 3 + 42;
    }

    @ChimeraEntangle
    public static long gold(long base) {
        return base * 13L + 7L;
    }

    @ChimeraEntangle
    public static double ratio(int a, int b) {
        return (double) (a + b) / (b + 1) + 0.5d;
    }
}
