package dev.chimera.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

/**
 * Guards {@link ChimeraEngine#RUNTIME_CLASSES}, the hand-written list of runtime classes injected
 * into every product jar.
 *
 * <p>The list has silently dropped a required class three times, and the third time
 * ({@code ChimeraPreLaunch$1}, an anonymous class added with the panel's {@code register} action) it
 * broke onboarding for every new customer while all licensed tests stayed green. This test runs the
 * same check the build runs, so the failure lands in CI instead of in a player's launcher.</p>
 */
class RuntimeClassListTest {

    @Test
    void whitelistMatchesTheCompiledRuntimeClasses() {
        assertDoesNotThrow(ChimeraEngine::verifyRuntimeClasses,
                "RUNTIME_CLASSES must list every runtime class the product needs, including "
                        + "anonymous inner classes");
    }
}
