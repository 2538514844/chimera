package demo;

import dev.chimera.annotations.ChimeraVM;

public final class VmCalc {
    private VmCalc() {
    }

    @ChimeraVM
    public static int addMul(int a, int b) {
        return a + b * 3;
    }
}
