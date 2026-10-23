package demo;

import dev.chimera.annotations.ChimeraEntangle;

public final class Damage {
    private Damage() {
    }

    @ChimeraEntangle
    public static int hit(int attack, int defense) {
        return attack * 7 - defense * 3 + 42;
    }

    @ChimeraEntangle
    public static double ratio(int a, int b) {
        return (double) (a + b) / (b + 1) + 0.5d;
    }
}
