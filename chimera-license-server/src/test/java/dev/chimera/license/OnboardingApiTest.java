package dev.chimera.license;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.chimera.license.store.LicenseStore;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Onboarding (2026-10-22): the operator reserves the HWID a customer sent in, the customer then
 * registers an account from that machine and is bound to it.
 *
 * <p>The properties under test are the ones that make exposing {@code /register} safe: a slot is
 * claimable once, an unreserved HWID is rejected, and a successful registration claims the slot
 * without binding a device (the first activation binds, because only it has the client's key).</p>
 */
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:chimera-onboarding-test;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.sql.init.mode=always",
        "license.key-dir=build/test-keys-onboarding",
        "license.content-key-hex=" + TestClientCrypto.MASTER_KEY_HEX,
        "license.build-token=test-build-token",
        // Self-registration is off by default in production; this suite is the one that exercises it.
        "license.self-register.enabled=true"
})
@AutoConfigureMockMvc
class OnboardingApiTest {

    private static final String TOKEN = "test-build-token";
    private static final String HWID = "a".repeat(64);
    private static final String OTHER_HWID = "b".repeat(64);

    @Autowired
    private MockMvc mvc;
    @Autowired
    private ObjectMapper json;
    @Autowired
    private LicenseStore store;

    @Test
    void reservedHwidRegistersAndDefersTheDeviceBindingToFirstActivation() throws Exception {
        reserve(HWID, "customer-1");
        assertEquals(200, register("newbie-1", "pw-newbie-1", HWID));
        LicenseStore.AccountRow row = store.findAccount("newbie-1").orElseThrow();
        // Registration claims the reservation but must NOT create the device row: it has no client
        // X25519 key yet, and a row with a NULL device_pub would let the next activation adopt any
        // key (red team round 4). The first activation binds, and it always has the key.
        assertEquals(0, store.devices(row.id()).size(),
                "registration must not bind a device before the client's key is known");
        assertEquals(row.id(), store.findReservation(HWID).orElseThrow().claimedAccountId());
    }

    @Test
    void secondRegistrationOnTheSameHwidIsRejected() throws Exception {
        String hwid = "c".repeat(64);
        reserve(hwid, "customer-2");
        assertEquals(200, register("newbie-2", "pw-newbie-2", hwid));
        // A different account name must not be able to take the same machine slot.
        assertEquals(409, register("newbie-2b", "pw-newbie-2b", hwid));
    }

    @Test
    void unreservedHwidIsRejectedAndLeavesNoAccount() throws Exception {
        assertEquals(403, register("newbie-3", "pw-newbie-3", OTHER_HWID));
        assertFalse(store.findAccount("newbie-3").isPresent());
    }

    @Test
    void duplicateAccountNameIsRejected() throws Exception {
        String hwid = "d".repeat(64);
        reserve(hwid, "customer-4");
        assertEquals(200, register("newbie-4", "pw-newbie-4", hwid));
        String otherHwid = "e".repeat(64);
        reserve(otherHwid, "customer-5");
        assertEquals(409, register("newbie-4", "pw-newbie-4", otherHwid));
    }

    @Test
    void adminReservationListShowsClaimedState() throws Exception {
        String hwid = "f".repeat(64);
        reserve(hwid, "customer-6");
        String body = mvc.perform(get("/api/v1/license/admin/reservations")
                        .header("X-Build-Token", TOKEN))
                .andReturn().getResponse().getContentAsString();
        var reservations = json.readTree(body).get("reservations");
        boolean found = false;
        for (var entry : reservations) {
            if (hwid.equals(entry.get("hwid").asText())) {
                found = true;
                assertFalse(entry.get("claimed").asBoolean());
            }
        }
        assertTrue(found, "reservation must be listed");
    }

    // ------------------------------------------------------------------ helpers

    private void reserve(String hwid, String note) throws Exception {
        String body = "{\"hwid\":\"" + hwid + "\",\"note\":\"" + note + "\"}";
        mvc.perform(post("/api/v1/license/admin/reserve-hwid")
                        .header("X-Build-Token", TOKEN)
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(r -> assertEquals(200, r.getResponse().getStatus()));
    }

    private int register(String account, String password, String hwid) throws Exception {
        String body = "{\"account\":\"" + account + "\",\"password\":\"" + password
                + "\",\"hwid\":\"" + hwid + "\"}";
        return mvc.perform(post("/api/v1/license/register")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andReturn().getResponse().getStatus();
    }
}
