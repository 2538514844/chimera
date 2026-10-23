package dev.chimera.license;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import dev.chimera.license.service.LicenseService;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/** Operator admin API: user listing, ban/unban and force-revoke (X-Build-Token protected). */
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:chimera-admin-test;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.sql.init.mode=always",
        "license.key-dir=build/test-keys-admin",
        "license.content-key-hex=" + TestClientCrypto.MASTER_KEY_HEX,
        "license.build-token=test-build-token"
})
@AutoConfigureMockMvc
class AdminApiTest {

    private static final String TOKEN = "test-build-token";

    @Autowired
    private MockMvc mvc;
    @Autowired
    private ObjectMapper json;
    @Autowired
    private LicenseService service;

    @Test
    void adminEndpointsRequireBuildToken() throws Exception {
        mvc.perform(get("/api/v1/license/admin/accounts")).andExpect(r ->
                assertEquals(403, r.getResponse().getStatus()));
        mvc.perform(post("/api/v1/license/admin/ban").contentType(MediaType.APPLICATION_JSON)
                .content("{\"account\":\"nobody\"}")).andExpect(r ->
                assertEquals(403, r.getResponse().getStatus()));
    }

    @Test
    void banAndUnbanReflectInAccountList() throws Exception {
        service.registerAccount("admin-ban-user", "pw-admin-ban");

        mvc.perform(post("/api/v1/license/admin/ban").header("X-Build-Token", TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"account\":\"admin-ban-user\"}"))
                .andExpect(r -> assertEquals(200, r.getResponse().getStatus()));
        assertEquals("BANNED", statusOf("admin-ban-user"));

        mvc.perform(post("/api/v1/license/admin/ban").header("X-Build-Token", TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"account\":\"missing-user\"}"))
                .andExpect(r -> assertEquals(404, r.getResponse().getStatus()));

        mvc.perform(post("/api/v1/license/admin/unban").header("X-Build-Token", TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"account\":\"admin-ban-user\"}"))
                .andExpect(r -> assertEquals(200, r.getResponse().getStatus()));
        assertEquals("ACTIVE", statusOf("admin-ban-user"));
    }

    @Test
    void revokeReportsSessionCountAndValidatesAccount() throws Exception {
        service.registerAccount("revoke-user", "pw-revoke-user");
        var result = mvc.perform(post("/api/v1/license/admin/revoke").header("X-Build-Token", TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"account\":\"revoke-user\"}")).andReturn();
        assertEquals(200, result.getResponse().getStatus());
        JsonNode body = json.readTree(result.getResponse().getContentAsString());
        assertTrue(body.get("sessions").asInt() >= 0);

        mvc.perform(post("/api/v1/license/admin/revoke").header("X-Build-Token", TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"account\":\"missing-user\"}"))
                .andExpect(r -> assertEquals(404, r.getResponse().getStatus()));
    }

    private String statusOf(String account) throws Exception {
        JsonNode body = json.readTree(mvc.perform(get("/api/v1/license/admin/accounts")
                .header("X-Build-Token", TOKEN)).andReturn().getResponse()
                .getContentAsString());
        for (JsonNode node : body.get("accounts")) {
            if (account.equals(node.get("account").asText())) {
                return node.get("status").asText();
            }
        }
        return "MISSING";
    }
}
