package dev.chimera.license.api;

import dev.chimera.license.config.KeyStoreService;
import dev.chimera.license.config.ResourceKeyService;
import dev.chimera.license.config.WatermarkKeyService;
import dev.chimera.license.crypto.CryptoUtils;
import dev.chimera.license.service.LicenseService;
import dev.chimera.license.store.LicenseStore;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;

/** License protocol endpoints (docs/AUTH-V2-PROTOCOL.md §3). */
@RestController
@RequestMapping("/api/v1/license")
public class LicenseController {

    private final LicenseService service;
    private final LicenseStore store;
    private final KeyStoreService keys;
    private final ResourceKeyService resourceKeys;
    private final WatermarkKeyService watermarkKeys;
    private final String buildToken;
    private final boolean selfRegisterEnabled;

    public LicenseController(LicenseService service, LicenseStore store, KeyStoreService keys,
                             ResourceKeyService resourceKeys, WatermarkKeyService watermarkKeys,
                             @Value("${license.build-token:}") String buildToken,
                             @Value("${license.self-register.enabled:false}")
                             boolean selfRegisterEnabled) {
        this.service = service;
        this.store = store;
        this.keys = keys;
        this.resourceKeys = resourceKeys;
        this.watermarkKeys = watermarkKeys;
        this.buildToken = buildToken;
        this.selfRegisterEnabled = selfRegisterEnabled;
    }

    // SECURITY (2026-10-22): the v3 /activate and /heartbeat endpoints were removed. v3 heartbeat
    // authenticated with a bearer token only - no HWID, no client key, no request signature - so a
    // leaked token could be renewed forever. v4 is now the only auth path (the customer is not
    // permitted to build their own client, so there is no compatibility requirement).

    /** Build-pipeline account provisioning; requires the X-Build-Token header. */
    @PostMapping("/admin/account")
    public Map<String, Object> createAccount(
            @RequestHeader(value = "X-Build-Token", required = false) String token,
            @RequestBody Map<String, String> body) {
        // Was an inline String.equals (short-circuiting, i.e. timing-observable); every other admin
        // endpoint already goes through requireAdminToken, which compares in constant time.
        requireAdminToken(token);
        service.registerAccount(body.get("account"), body.get("password"));
        return Map.of("status", "CREATED");
    }

    /** Operator ban: account status becomes BANNED and all active sessions are revoked. */
    @PostMapping("/admin/ban")
    public Map<String, Object> ban(
            @RequestHeader(value = "X-Build-Token", required = false) String token,
            @RequestBody Map<String, String> body) {
        requireAdminToken(token);
        String account = body.get("account");
        int updated = store.updateAccountStatus(account, "BANNED");
        if (updated == 0) {
            throw new LicenseException(404, "E_ACCOUNT_NOT_FOUND");
        }
        Optional<LicenseStore.AccountRow> row = store.findAccount(account);
        row.ifPresent(accountRow -> store.revokeSessions(accountRow.id()));
        return Map.of("status", "BANNED", "account", account);
    }

    @PostMapping("/admin/unban")
    public Map<String, Object> unban(
            @RequestHeader(value = "X-Build-Token", required = false) String token,
            @RequestBody Map<String, String> body) {
        requireAdminToken(token);
        String account = body.get("account");
        if (store.updateAccountStatus(account, "ACTIVE") == 0) {
            throw new LicenseException(404, "E_ACCOUNT_NOT_FOUND");
        }
        return Map.of("status", "ACTIVE", "account", account);
    }

    /** Force-logout: revoke all sessions so the next heartbeat fails. */
    @PostMapping("/admin/revoke")
    public Map<String, Object> revoke(
            @RequestHeader(value = "X-Build-Token", required = false) String token,
            @RequestBody Map<String, String> body) {
        requireAdminToken(token);
        String account = body.get("account");
        LicenseStore.AccountRow row = store.findAccount(account)
                .orElseThrow(() -> new LicenseException(404, "E_ACCOUNT_NOT_FOUND"));
        int revoked = store.revokeSessions(row.id());
        return Map.of("status", "REVOKED", "account", account, "sessions", revoked);
    }

    /**
     * Operator action for "player replaced hardware": clears the account's bound devices, so the
     * next activation binds whatever machine the player now has.
     *
     * <p>Deliberately admin-only. The product owner's decision (2026-10-22) is that a hardware
     * change is the customer's own business and support handles it - there is no self-service
     * rebind, so a stolen token cannot re-bind itself to a new machine. Pass {@code hwid} to bind
     * it directly (useful when support has the value from the player's log).</p>
     */
    @PostMapping("/admin/rebind")
    public Map<String, Object> rebind(
            @RequestHeader(value = "X-Build-Token", required = false) String token,
            @RequestBody Map<String, String> body) {
        requireAdminToken(token);
        String account = body.get("account");
        LicenseStore.AccountRow row = store.findAccount(account)
                .orElseThrow(() -> new LicenseException(404, "E_ACCOUNT_NOT_FOUND"));
        int cleared = store.deleteDevices(row.id());
        // Red team round 4 (source audit): clearing the binding without revoking the live sessions
        // left the old machine heartbeating forever (it renews expires_at every minute). Support
        // "unbinding" a player has to actually take that player offline.
        int revoked = store.revokeSessions(row.id());
        String hwid = body.get("hwid");
        boolean bound = false;
        if (hwid != null && hwid.matches("[0-9a-fA-F]{64}")) {
            store.bindDevice(row.id(), hwid.toLowerCase(java.util.Locale.ROOT),
                    java.time.Instant.now());
            bound = true;
        } else if (hwid != null && !hwid.isBlank()) {
            throw new LicenseException(400, "E_BAD_HWID");
        }
        store.audit(row.id(), bound ? "REBIND_HWID_BOUND" : "REBIND_HWID_CLEARED", null, null);
        return Map.of("status", "REBOUND", "account", account, "devicesCleared", cleared,
                "sessionsRevoked", revoked, "bound", bound);
    }

    /**
     * Self-service registration against a pre-registered hardware slot.
     *
     * <p>Public on purpose (that is the onboarding flow): the operator reserves the HWID the customer
     * sent over chat, the customer picks their own account name and password from that machine, and
     * the reservation binds them together. Safety comes from the reservation being single-claim and
     * from the caller having to present the exact 64-hex HWID.</p>
     */
    @PostMapping("/register")
    public Map<String, Object> register(@RequestBody Map<String, String> body,
                                        HttpServletRequest http) {
        // Off by default. A deployment where the operator opens accounts with /admin/account has no
        // use for a public write endpoint, and every public write endpoint is attack surface; the
        // reservation flow is only meaningful when the *operator* is the one reserving HWIDs.
        if (!selfRegisterEnabled) {
            throw new LicenseException(410, "E_SELF_REGISTER_DISABLED");
        }
        service.registerWithReservedHwid(body.get("account"), body.get("password"),
                body.get("hwid"), http.getRemoteAddr());
        return Map.of("status", "CREATED", "account", body.get("account") == null
                ? "" : body.get("account").trim());
    }

    /** Operator onboarding step 1: add the HWID a customer sent in. */
    @PostMapping("/admin/reserve-hwid")
    public Map<String, Object> reserveHwid(
            @RequestHeader(value = "X-Build-Token", required = false) String token,
            @RequestBody Map<String, String> body) {
        requireAdminToken(token);
        String hwid = body.get("hwid");
        if (hwid == null || !hwid.trim().matches("[0-9a-fA-F]{64}")) {
            throw new LicenseException(400, "E_BAD_HWID");
        }
        String normalized = hwid.trim().toLowerCase(java.util.Locale.ROOT);
        store.reserveHwid(normalized, body.get("note"));
        return Map.of("status", "RESERVED", "hwid", normalized);
    }

    /** Operator view: which slots are still unclaimed. */
    @GetMapping("/admin/reservations")
    public Map<String, Object> reservations(
            @RequestHeader(value = "X-Build-Token", required = false) String token) {
        requireAdminToken(token);
        return Map.of("reservations", store.listReservations().stream()
                .map(row -> Map.of("hwid", row.hwid(),
                        "note", row.note() == null ? "" : row.note(),
                        "claimed", row.claimedAccountId() != null))
                .toList());
    }

    @GetMapping("/admin/accounts")
    public Map<String, Object> accounts(
            @RequestHeader(value = "X-Build-Token", required = false) String token) {
        requireAdminToken(token);
        return Map.of("accounts", store.listAccounts().stream()
                .map(row -> Map.of("id", row.id(), "account", row.account(),
                        "status", row.status()))
                .toList());
    }

    private void requireAdminToken(String token) {
        // Red team round 4 (source audit): String.equals short-circuits on the first differing byte,
        // so the comparison leaked the token's prefix through response timing. The /resource-key
        // endpoint already used a constant-time compare; this is the one every other admin endpoint
        // goes through, so it is the one that mattered.
        if (buildToken == null || buildToken.isBlank() || token == null
                || !CryptoUtils.constantTimeEquals(
                        buildToken.getBytes(StandardCharsets.UTF_8),
                        token.getBytes(StandardCharsets.UTF_8))) {
            throw new LicenseException(403, "E_FORBIDDEN");
        }
    }

    @GetMapping("/pubkey")
    public Map<String, String> publicKey() {
        return Map.of("pubkey", keys.publicKeyBase64());
    }

    /**
     * #19: the watermark RSA public key the build bakes into the client ({@code -WmPubKeyB64}).
     * Public by design - it only lets a client seal a payload, never read one. The private key is
     * what the operator keeps to trace a leaked build.
     */
    @GetMapping("/wm-pubkey")
    public Map<String, String> watermarkPublicKey() {
        return Map.of("wm_pubkey", watermarkKeys.publicKeyBase64());
    }

    /**
     * Build-pipeline only: returns the ResourceKey that must be used to encrypt paid resources.
     * Disabled unless {@code license.build-token} / {@code CHIMERA_BUILD_TOKEN} is configured.
     * The MasterKey is never returned by any endpoint.
     */
    @GetMapping("/resource-key")
    public ApiModels.BuildResourceKeyResponse resourceKey(
            @RequestHeader(value = "X-Chimera-Build-Token", required = false) String presentedToken) {
        if (buildToken == null || buildToken.isBlank()) {
            throw new LicenseException(404, "E_NOT_FOUND");
        }
        if (presentedToken == null || !CryptoUtils.constantTimeEquals(
                buildToken.getBytes(StandardCharsets.UTF_8),
                presentedToken.getBytes(StandardCharsets.UTF_8))) {
            throw new LicenseException(401, "E_AUTH");
        }
        return new ApiModels.BuildResourceKeyResponse(resourceKeys.resourceKeyBase64(),
                resourceKeys.fingerprint());
    }
}
