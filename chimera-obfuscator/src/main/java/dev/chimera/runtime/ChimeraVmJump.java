package dev.chimera.runtime;

/**
 * Control-flow signal used by the M9 interpreter: jumps are thrown/caught instead of a plain
 * switch assignment, which breaks the natural CFG shape of the interpreter loop.
 * Injected into the protected jar with the other runtime classes.
 */
public final class ChimeraVmJump extends RuntimeException {

    public final int target;

    public ChimeraVmJump(int target) {
        super(null, null, false, false);
        this.target = target;
    }
}
