package demo;

import dev.chimera.annotations.ChimeraProtected;

public final class Bonus {
    @ChimeraProtected
    public int calc(int base) {
        return base * 7 + 3;
    }
}
