package dev.chimera.runtime;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** G7 gate semantics: release builds must block until the license is valid. */
class ChimeraPreLaunchTest {

    @Test
    void releaseWithoutLicenseBlocks() {
        assertTrue(ChimeraPreLaunch.shouldBlock(false, false));
    }

    @Test
    void releaseWithLicensePasses() {
        assertFalse(ChimeraPreLaunch.shouldBlock(false, true));
    }

    @Test
    void devBypassSkipsTheGate() {
        assertFalse(ChimeraPreLaunch.shouldBlock(true, false));
    }

    @Test
    void failureCopyCarriesStableCodes() {
        assertEquals(true, ChimeraActivationPanel.describe(
                ChimeraActivationPanel.ActivationResult.fail(
                        ChimeraActivationPanel.Status.E_EXPIRED, "")).startsWith("E_EXPIRED"));
        assertEquals(true, ChimeraActivationPanel.describe(
                ChimeraActivationPanel.ActivationResult.fail(
                        ChimeraActivationPanel.Status.E_HWID, "")).startsWith("E_HWID"));
        assertEquals(true, ChimeraActivationPanel.describe(
                ChimeraActivationPanel.ActivationResult.ok(0L, "tag")).startsWith("ACTIVATED"));
    }

    /**
     * P0-1: an enforced artifact whose gate never recorded an authorized licence must halt at the
     * post-gate entrypoint (patched gate, deleted release resources, flipped env.dat flag).
     */
    @Test
    void postGateHaltsOnlyForUnauthorizedEnforcedArtifact() {
        assertTrue(ChimeraPreLaunch.postGateMustHalt(false, true));
        assertFalse(ChimeraPreLaunch.postGateMustHalt(true, true));
        assertFalse(ChimeraPreLaunch.postGateMustHalt(false, false));
        assertFalse(ChimeraPreLaunch.postGateMustHalt(true, false));
    }

    /**
     * The enforcement point must be safe for dev artifacts and for licensed starts: unit tests run
     * on a dev DLL without release resources, so the check has to return instead of exiting the JVM.
     */
    @Test
    void postGateCheckReturnsForDevArtifact() {
        ChimeraPreLaunch.resetForTests();
        assertEquals(false, ChimeraRuntime.enforceReleasePolicy());
        ChimeraPreLaunch.requireGateAuthorized("unit-test"); // must not halt
        ChimeraPreLaunch.markAuthorizedForTests();
        ChimeraPreLaunch.requireGateAuthorized("unit-test"); // authorized path
        ChimeraPreLaunch.resetForTests();
    }

    @Test
    void headlessPanelFailsClosed() {
        ChimeraActivationPanel panel = new ChimeraActivationPanel(null, "hwid");
        if (java.awt.GraphicsEnvironment.isHeadless()) {
            assertFalse(panel.showBlocking().activated());
        }
    }
}
