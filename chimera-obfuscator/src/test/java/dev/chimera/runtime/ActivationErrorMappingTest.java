package dev.chimera.runtime;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the server-code to user-facing-status mapping.
 *
 * <p>Red team round 4 found that only five codes were recognised and everything else fell through to
 * {@code E_NETWORK}, so a banned account, a wrong password and a device mismatch all told the user
 * to "check your connection and retry" - the three cases where retrying can never work. These tests
 * pin the split: no response at all is a network problem, a refusal from the server never is.</p>
 */
class ActivationErrorMappingTest {

    @Test
    void noResponseIsTheOnlyNetworkFailure() {
        assertEquals(ChimeraActivationPanel.Status.E_NETWORK, ChimeraV4Session.mapError(null),
                "only a missing response means 'the server is unreachable'");
    }

    @Test
    void credentialsAndDeviceProblemsKeepTheirOwnMeaning() {
        assertEquals(ChimeraActivationPanel.Status.E_CREDENTIALS,
                ChimeraV4Session.mapError("E_AUTH"));
        for (String code : new String[]{"E_HWID", "E_HWID_MISMATCH", "E_DEVICE_KEY_MISMATCH",
                "E_BINDING", "E_DEVICE_LIMIT"}) {
            assertEquals(ChimeraActivationPanel.Status.E_HWID, ChimeraV4Session.mapError(code),
                    code + " must surface as a device problem");
        }
    }

    @Test
    void bannedOrRevokedIsTerminal() {
        for (String code : new String[]{"E_REVOKED", "E_ACCOUNT_NOT_FOUND"}) {
            assertEquals(ChimeraActivationPanel.Status.E_REVOKED, ChimeraV4Session.mapError(code),
                    code + " must surface as banned/revoked, not as a transient failure");
        }
    }

    @Test
    void unknownCodesAreRejectionsNotNetworkErrors() {
        assertEquals(ChimeraActivationPanel.Status.E_REJECTED,
                ChimeraV4Session.mapError("E_SOMETHING_NEW_IN_A_LATER_SERVER"));
    }

    @Test
    void everyStatusHasUserVisibleCopyAndTerminalOnesDoNotBlameTheNetwork() {
        for (ChimeraActivationPanel.Status status : ChimeraActivationPanel.Status.values()) {
            String text = ChimeraActivationPanel.describe(
                    ChimeraActivationPanel.ActivationResult.fail(status, ""));
            assertNotNull(text);
            assertFalse(text.isBlank(), status + " has no user-visible copy");
            if (status == ChimeraActivationPanel.Status.E_NETWORK
                    || status == ChimeraActivationPanel.Status.ACTIVATED) {
                continue;
            }
            assertFalse(text.toLowerCase(java.util.Locale.ROOT).contains("connection"),
                    status + " must not tell the user to check the network: " + text);
        }
    }

    @Test
    void describePrefixesTheStableCodeForSupport() {
        String text = ChimeraActivationPanel.describe(ChimeraActivationPanel.ActivationResult
                .fail(ChimeraActivationPanel.Status.E_CREDENTIALS, ""));
        assertTrue(text.startsWith("E_CREDENTIALS"), "support needs the stable code: " + text);
    }
}
