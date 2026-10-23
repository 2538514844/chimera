package dev.chimera.runtime;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * G7/F: minimal v4 licensing client used by the activation gate. JDK-only on purpose: it runs
 * before Minecraft loads, so it must not depend on any transformed or game class.
 *
 * <p>The server seals the product ResourceKey for the client's ephemeral X25519 key
 * (HKDF info "chimera/v1/v4/ck", AAD "chimera/v1/v4/ck|account|hwid"); this class verifies the
 * Ed25519 response signature, unwraps the key and persists it for the next launch.</p>
 */
public final class ChimeraV4Session {

    private static final String V4_ACTIVATE = "/api/v1/license/v4/activate";
    private static final String V4_HEARTBEAT = "/api/v1/license/v4/heartbeat";
    private static final String V4_REGISTER = "/api/v1/license/register";
    private static final String HEARTBEAT_DOMAIN = "chimera-auth-v4/heartbeat-response";
    private static final String ACTIVATE_DOMAIN = "chimera-auth-v4/activate-response";
    /**
     * Signed activate-response fields, in wire order (the transcript is domain + version + these).
     *
     * <p>{@code license_id} and {@code client_ip} were appended on 2026-10-22 (task #17) and must
     * match {@code AuthTranscriptV4.activateResponse} on the server byte for byte. They are signed,
     * so the licence id the watermark embeds cannot be substituted by a modified client.</p>
     */
    private static final String[] ACTIVATE_ORDER = {"account", "hwid", "client_ephemeral_pub",
            "client_nonce", "server_ephemeral_pub", "server_nonce", "token", "sequence",
            "issued_at", "expires_at", "server_time", "resource_ck", "license_id", "client_ip"};
    /** Signed heartbeat-response fields, in wire order (after domain + version). */
    private static final String[] HEARTBEAT_ORDER = {"token", "sequence", "server_nonce",
            "issued_at", "expires_at", "server_time", "resource_ck", "server_ephemeral_pub",
            "license_id", "client_ip"};
    private static final byte[] ED25519_X509_PREFIX =
            java.util.HexFormat.of().parseHex("302a300506032b6570032100");
    private static final byte[] X25519_X509_PREFIX =
            java.util.HexFormat.of().parseHex("302a300506032b656e032100");

    private final String server;
    private final byte[] pinnedPub;
    private final String hwid;
    private final Path stateFile;
    /**
     * DPAPI-sealed client X25519 key ({@code ck.bin}), next to the session state file. The server
     * binds a v4 session to the public key captured at activation, so this blob is what keeps
     * restart-without-re-activation working; it is opaque to this class (only the DLL can unseal
     * it) and it only unseals for the Windows user who activated.
     */
    private final Path clientKeyFile;
    /**
     * Stable licence id issued (and signed) by the server, cached from the last activate/heartbeat.
     * Null until a response has been seen; the per-licence watermark must treat a missing value as
     * "no watermark" rather than inventing one.
     */
    private volatile String licenseId;
    /** Account name of the current session (set by activate/heartbeat/state restore). */
    private volatile String account;
    /**
     * Client address as reported (and signed) by the server in the last response. The client cannot
     * discover its own public address, so this is the only trustworthy source for the watermark's
     * {@code ip} field.
     */
    private volatile String clientIp = "";
    /**
     * #19b: Ed25519 signature over {@code "chimera-wm-v1|licenseId|account"}, issued at activation.
     * Embedded in the watermark payload so a forged payload cannot name somebody else's licence.
     */
    private volatile String watermarkSignature = "";

    private ChimeraV4Session(String server, byte[] pinnedPub, String hwid, Path stateFile) {
        this.server = server;
        this.pinnedPub = pinnedPub;
        this.hwid = hwid;
        this.stateFile = stateFile;
        this.clientKeyFile = stateFile == null ? null : stateFile.resolveSibling("ck.bin");
    }

    /**
     * The signed licence id of the current session, or {@code null} when none has been seen yet.
     * Used by the per-licence watermark (#19); never log or display it.
     */
    public String licenseId() {
        return licenseId;
    }

    /** Account name of the current session, or {@code null} before the first response. */
    public String account() {
        return account;
    }

    /** #19b: signature binding the watermark payload's licence id + account, empty when unknown. */
    public String watermarkSignature() {
        return watermarkSignature == null ? "" : watermarkSignature;
    }

    /** Client address reported by the server (signed), empty when unknown. */
    public String clientIp() {
        return clientIp == null ? "" : clientIp;
    }

    /** Explicit factory used by build tooling and end-to-end tests (no baked auth.dat needed). */
    public static ChimeraV4Session create(String server, byte[] pinnedEd25519Raw, String hwid,
                                          Path stateFile) {
        if (server == null || server.isBlank() || pinnedEd25519Raw == null
                || pinnedEd25519Raw.length != 32 || hwid == null || hwid.isBlank()) {
            throw new IllegalArgumentException("server, 32-byte pinned key and hwid are required");
        }
        return new ChimeraV4Session(server.replaceAll("/+$", ""), pinnedEd25519Raw.clone(),
                hwid, stateFile);
    }

    /** @return a client when the baked auth.dat configures a server and public key */
    public static ChimeraV4Session create(String hwid) {
        Map<String, String> config = authConfig();
        String server = config.get("server");
        String pubkey = config.get("pubkey");
        if (server == null || pubkey == null || server.isBlank() || pubkey.isBlank()) {
            return null;
        }
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(pubkey.trim());
        } catch (RuntimeException invalid) {
            return null;
        }
        if (raw.length != 32) {
            return null;
        }
        Path state = Path.of(System.getProperty("user.home", "."), ".chimera", "license.dat");
        return new ChimeraV4Session(server.replaceAll("/+$", ""), raw, hwid, state);
    }

    private static Map<String, String> authConfig() {
        Map<String, String> config = new LinkedHashMap<>();
        try (InputStream in = ChimeraV4Session.class.getResourceAsStream("/chimera/auth.dat")) {
            if (in == null) {
                return config;
            }
            String text = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            for (String line : text.split("\\R")) {
                int eq = line.indexOf('=');
                if (eq > 0) {
                    config.put(line.substring(0, eq).trim(), line.substring(eq + 1).trim());
                }
            }
        } catch (Throwable ignored) {
            // missing/unreadable config -> not available
        }
        return config;
    }

    /** Result of one activation round-trip. */
    public record Result(ChimeraActivationPanel.Status status, String detail,
                         long expiresAtEpochSeconds, String token, long sequence,
                         long handle) {
        static Result fail(ChimeraActivationPanel.Status status, String detail) {
            return new Result(status, detail, 0L, "", 0L, 0L);
        }

        public boolean activated() {
            return status == ChimeraActivationPanel.Status.ACTIVATED;
        }
    }

    /** Activates and returns the unwrapped ResourceKey (caller installs it). */
    public Result activate(String account, char[] password) {
        try {
            // The native verifier needs the pinned server key in this process.
            ChimeraRuntime.nativeSetAuthContext(pinnedPub,
                    account.getBytes(StandardCharsets.UTF_8));
            // Best effort: keep the existing key pair so a re-activation does not rotate the
            // client identity. A blob from another user/machine is ignored here on purpose -
            // a credentialed activation re-binds the public key server-side anyway.
            loadClientKey();
            byte[] begin = new byte[48];
            int beginCode = ChimeraRuntime.nativeAuthV4Begin(begin);
            if (beginCode != 0) {
                // -6: the persisted key exists but cannot be unsealed here (other Windows user or
                // machine, tampered blob) - a state problem, not a signature problem.
                return Result.fail(beginCode == -6
                        ? ChimeraActivationPanel.Status.E_STATE : nativeStatus(beginCode),
                        "native begin " + beginCode);
            }
            String clientPub = Base64.getEncoder().encodeToString(Arrays.copyOfRange(begin, 0, 32));
            byte[] nonceBytes = Arrays.copyOfRange(begin, 32, 48);
            String clientNonce = hex(nonceBytes);

            Map<String, Object> request = new LinkedHashMap<>();
            request.put("v", 4);
            request.put("account", account);
            request.put("password", new String(password));
            request.put("hwid", hwid);
            request.put("client_ephemeral_pub", clientPub);
            request.put("client_nonce", clientNonce);
            String body = post(server + V4_ACTIVATE, toJson(request));
            if (body == null) {
                return Result.fail(ChimeraActivationPanel.Status.E_NETWORK, "no response");
            }
            Map<String, String> fields = parseFlatJson(body);
            if (fields.containsKey("error")) {
                return Result.fail(mapError(fields.get("error")), fields.get("error"));
            }
            String signature = fields.get("signature");
            String serverPubB64 = fields.get("server_ephemeral_pub");
            String resourceCk = fields.get("resource_ck");
            if (signature == null || serverPubB64 == null || resourceCk == null) {
                return Result.fail(ChimeraActivationPanel.Status.E_SIGNATURE, "missing fields");
            }
            // All cryptography runs inside the DLL: signature verification, X25519, HKDF and the
            // AES-GCM unwrap. Java only forwards the response bytes and receives a handle id.
            long handle = ChimeraRuntime.nativeAuthV4Finish(
                    canonicalResponse(fields),
                    Base64.getDecoder().decode(signature),
                    Base64.getDecoder().decode(serverPubB64),
                    Base64.getDecoder().decode(resourceCk),
                    account.getBytes(StandardCharsets.UTF_8),
                    hwid.getBytes(StandardCharsets.UTF_8));
            if (handle <= 0) {
                return Result.fail(nativeStatus(handle), "native finish " + handle);
            }
            long expires = parseLong(fields.get("expires_at"));
            long sequence = parseLong(fields.get("sequence"));
            String token = fields.getOrDefault("token", "");
            // #17/#19: signed licence id and observed client address, persisted with the session.
            clientIp = fields.getOrDefault("client_ip", "");
            watermarkSignature = fields.getOrDefault("wm_sig", "");
            diag("wm_sig len=" + watermarkSignature.length());
            // Seal the freshly generated key pair before the session state is written: the state
            // key below is derived from this blob, and the next launch needs both files.
            if (!persistClientKey()) {
                // Not fatal for this launch (the native handle is already valid), but the next
                // start fails closed and asks for re-activation instead of silently rotating.
                diag("client key persist failed; restart will require re-activation");
            }
            persist(account, handle, token, sequence, expires, fields.getOrDefault("license_id", ""));
            return new Result(ChimeraActivationPanel.Status.ACTIVATED, "", expires, token,
                    sequence, handle);
        } catch (Throwable failure) {
            return Result.fail(ChimeraActivationPanel.Status.E_NETWORK,
                    String.valueOf(failure.getMessage()));
        }
    }

    private static ChimeraActivationPanel.Status nativeStatus(long code) {
        return switch ((int) code) {
            case -6, -7 -> ChimeraActivationPanel.Status.E_SIGNATURE;
            case -8, -9, -10 -> ChimeraActivationPanel.Status.E_SIGNATURE;
            case -5 -> ChimeraActivationPanel.Status.E_HWID;
            default -> ChimeraActivationPanel.Status.E_STATE;
        };
    }

    /** Canonical activate-response transcript (domain + version + {@link #ACTIVATE_ORDER}). */
    static byte[] canonicalResponse(Map<String, String> fields) throws Exception {
        java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();
        java.io.DataOutputStream out = new java.io.DataOutputStream(buffer);
        transcript(out, ACTIVATE_DOMAIN);
        transcript(out, "4");
        for (String field : ACTIVATE_ORDER) {
            transcript(out, fields.getOrDefault(field, ""));
        }
        return buffer.toByteArray();
    }

    /** @return persisted ResourceKey when the local state is present and unexpired */
    /** @return native handle when the persisted state is present and still valid, else 0 */
    public long authorizedHandle() {
        try {
            diag("authorizedHandle state=" + stateFile + " exists=" + Files.isRegularFile(stateFile));
            if (!Files.isRegularFile(stateFile)) {
                return 0L;
            }
            byte[] stateKey = stateKey();
            if (stateKey == null) {
                // Fail closed: without the DPAPI-sealed client key there is nothing to heartbeat
                // with, and the state file itself cannot be decrypted.
                diag("state key unavailable (missing client key blob)");
                return 0L;
            }
            byte[] plain = aesGcmOpen(stateKey, Files.readAllBytes(stateFile), null);
            if (plain == null) {
                diag("state decrypt failed");
                return 0L;
            }
            Map<String, String> state = new LinkedHashMap<>();
            for (String line : new String(plain, StandardCharsets.UTF_8).split("\\R")) {
                int eq = line.indexOf('=');
                if (eq > 0) {
                    state.put(line.substring(0, eq), line.substring(eq + 1));
                }
            }
            if (!hwid.equals(state.get("hwid"))) {
                diag("hwid mismatch: file=" + state.get("hwid") + " current=" + hwid);
                return 0L;
            }
            // #17: restore the licence id persisted with the session; the next heartbeat refreshes
            // it from the signed response.
            String storedLicenseId = state.get("license_id");
            if (storedLicenseId != null && !storedLicenseId.isBlank()) {
                licenseId = storedLicenseId;
            }
            String storedAccount = state.get("account");
            if (storedAccount != null && !storedAccount.isBlank()) {
                account = storedAccount;
            }
            String storedIp = state.get("client_ip");
            if (storedIp != null) {
                clientIp = storedIp;
            }
            String storedSig = state.get("wm_sig");
            if (storedSig != null) {
                watermarkSignature = storedSig;
            }
            long handle = parseLong(state.get("handle"));
            int status = handle == 0L ? -1 : ChimeraRuntime.nativeAuthV4Status(handle);
            diag("restore handle=" + handle + " status=" + status
                    + " account=" + state.get("account") + " tokenLen="
                    + (state.get("token") == null ? -1 : state.get("token").length()));
            if (handle != 0L && status == 1) {
                return handle;
            }
            // Handle tables are per-process: a new launch renews the session through heartbeat,
            // which lets the server re-wrap the ResourceKey for this process's native key.
            String account = state.get("account");
            String token = state.get("token");
            long sequence = parseLong(state.get("sequence"));
            if (account == null || token == null || token.isEmpty()) {
                diag("restore missing account/token");
                return 0L;
            }
            // The heartbeat must present the public key the server bound at activation. A missing
            // or unreadable blob (other machine, other Windows user, tampered) means re-activation;
            // never let the native side mint a fresh key here.
            if (!loadClientKey()) {
                diag("client key unavailable -> re-activation required");
                return 0L;
            }
            return heartbeat(account, token, sequence);
        } catch (Throwable ignored) {
            return 0L;
        }
    }

    /**
     * E: one renewal round-trip for the periodic heartbeat.
     *
     * <p>Reads the persisted session, performs a normal v4 heartbeat (which rotates the token,
     * bumps the sequence and re-wraps the ResourceKey for this process's key) and returns the new
     * native handle. {@code 0} means the renewal failed - the caller decides what that costs.</p>
     *
     * <p>{@code synchronized}: the gate's restore path and the heartbeat thread must never present
     * the same sequence twice (the server would answer {@code E_SEQUENCE} and the session would be
     * burned).</p>
     */
    public synchronized long renew() {
        try {
            if (stateFile == null || !Files.isRegularFile(stateFile)) {
                return 0L;
            }
            byte[] stateKey = stateKey();
            if (stateKey == null) {
                diag("renew: state key unavailable");
                return 0L;
            }
            byte[] plain = aesGcmOpen(stateKey, Files.readAllBytes(stateFile), null);
            if (plain == null) {
                diag("renew: state decrypt failed");
                return 0L;
            }
            Map<String, String> state = new LinkedHashMap<>();
            for (String line : new String(plain, StandardCharsets.UTF_8).split("\\R")) {
                int eq = line.indexOf('=');
                if (eq > 0) {
                    state.put(line.substring(0, eq), line.substring(eq + 1));
                }
            }
            String currentAccount = state.get("account");
            String token = state.get("token");
            long sequence = parseLong(state.get("sequence"));
            if (currentAccount == null || token == null || token.isEmpty()) {
                diag("renew: missing account/token");
                return 0L;
            }
            if (!loadClientKey()) {
                diag("renew: client key unavailable (see the 'unseal REFUSED' line above for the "
                        + "actual reason)");
                return 0L;
            }
            return heartbeat(currentAccount, token, sequence);
        } catch (Throwable failure) {
            diag("renew failed: " + failure);
            return 0L;
        }
    }

    private static void diag(String line) {
        try {
            java.nio.file.Path dir = java.nio.file.Path.of(
                    System.getProperty("user.home", "."), ".chimera");
            java.nio.file.Files.createDirectories(dir);
            java.nio.file.Files.writeString(dir.resolve("gate-diag.log"),
                    line + System.lineSeparator(), java.nio.charset.StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE,
                    java.nio.file.StandardOpenOption.APPEND);
        } catch (Throwable ignored) {
            // diagnostics must never break startup
        }
    }

    private long heartbeat(String account, String token, long sequence) {
        diag("heartbeat start seq=" + sequence);
        try {
            ChimeraRuntime.nativeSetAuthContext(pinnedPub,
                    account.getBytes(StandardCharsets.UTF_8));
            byte[] begin = new byte[48];
            int beginCode = ChimeraRuntime.nativeAuthV4Begin(begin);
            if (beginCode != 0) {
                // -6 = the sealed key cannot be unsealed here: re-activation is the only way out.
                diag("heartbeat begin failed " + beginCode);
                return 0L;
            }
            String clientPub = Base64.getEncoder().encodeToString(Arrays.copyOfRange(begin, 0, 32));
            String clientNonce = hex(Arrays.copyOfRange(begin, 32, 48));
            Map<String, Object> request = new LinkedHashMap<>();
            request.put("v", 4);
            request.put("hwid", hwid);
            request.put("token", token);
            request.put("client_nonce", clientNonce);
            request.put("sequence", sequence);
            request.put("client_ephemeral_pub", clientPub);
            String body = post(server + V4_HEARTBEAT, toJson(request));
            if (body == null) {
                diag("heartbeat no response");
                return 0L;
            }
            // Never log the response body: it carries the rotated bearer token, the wrapped
            // ResourceKey and the server signature, and gate-diag.log is plaintext on disk while the
            // session state file next to it is AES-GCM sealed. Logging 200 characters of it every
            // 60 seconds handed a working session to anyone who could read the user's home
            // directory. Shape only.
            diag("heartbeat response: " + body.length() + " chars");
            Map<String, String> fields = parseFlatJson(body);
            if (fields.containsKey("error")) {
                return 0L;
            }
            String signature = fields.get("signature");
            String serverPubB64 = fields.get("server_ephemeral_pub");
            String resourceCk = fields.get("resource_ck");
            if (signature == null || serverPubB64 == null || resourceCk == null) {
                return 0L;
            }
            long newHandle = ChimeraRuntime.nativeAuthV4HeartbeatFinish(
                    canonicalHeartbeat(fields, token),
                    Base64.getDecoder().decode(signature),
                    Base64.getDecoder().decode(serverPubB64),
                    Base64.getDecoder().decode(resourceCk),
                    account.getBytes(StandardCharsets.UTF_8),
                    hwid.getBytes(StandardCharsets.UTF_8));
            if (newHandle <= 0L) {
                diag("heartbeat finish failed " + newHandle);
                return 0L;
            }
            diag("heartbeat ok handle issued");
            clientIp = fields.getOrDefault("client_ip", "");
            // #19b: heartbeat refreshes the watermark signature too, so an upgraded client does not
            // need to re-activate to get a verifiable mark.
            String renewedSig = fields.getOrDefault("wm_sig", "");
            if (!renewedSig.isEmpty()) {
                watermarkSignature = renewedSig;
            }
            diag("heartbeat wm_sig len=" + watermarkSignature.length());
            persist(account, newHandle, fields.getOrDefault("token", ""),
                    parseLong(fields.get("sequence")), parseLong(fields.get("expires_at")),
                    fields.getOrDefault("license_id", ""));
            return newHandle;
        } catch (Throwable failure) {
            diag("heartbeat exception " + failure);
            return 0L;
        }
    }

    private static byte[] canonicalHeartbeat(Map<String, String> fields, String presentedToken)
            throws Exception {
        java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();
        java.io.DataOutputStream out = new java.io.DataOutputStream(buffer);
        transcript(out, HEARTBEAT_DOMAIN);
        transcript(out, "4");
        // Server order: hwid, client_nonce, SHA256hex(presented token), new token, sequence,
        // server_nonce, issued_at, expires_at, server_time, resource_ck, server_ephemeral_pub,
        // license_id, client_ip (the last two are #17).
        transcript(out, fields.getOrDefault("hwid", ""));
        transcript(out, fields.getOrDefault("client_nonce", ""));
        transcript(out, tokenHashHex(presentedToken));
        for (String field : HEARTBEAT_ORDER) {
            transcript(out, fields.getOrDefault(field, ""));
        }
        return buffer.toByteArray();
    }

    private static String tokenHashHex(String token) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(token.getBytes(StandardCharsets.UTF_8));
        return hex(digest);
    }

    private void persist(String account, long handle, String token, long sequence, long expires,
                         String licenseIdValue)
            throws Exception {
        byte[] key = stateKey();
        if (key == null) {
            diag("state not written: client key blob unavailable");
            return;
        }
        if (licenseIdValue != null && !licenseIdValue.isBlank()) {
            this.licenseId = licenseIdValue;
        }
        if (account != null && !account.isBlank()) {
            this.account = account;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("hwid=").append(hwid).append('\n');
        sb.append("account=").append(account).append('\n');
        sb.append("handle=").append(handle).append('\n');
        sb.append("token=").append(token).append('\n');
        sb.append("sequence=").append(sequence).append('\n');
        sb.append("expires=").append(expires).append('\n');
        // #17: the signed licence id is kept next to the session so a restart (which renews through
        // heartbeat) still knows its own id before the first response arrives.
        sb.append("license_id=").append(licenseIdValue == null ? "" : licenseIdValue).append('\n');
        // #19: the signed client address is part of the watermark payload; the client has no other
        // way to learn its own public address.
        sb.append("client_ip=").append(clientIp == null ? "" : clientIp).append('\n');
        // #19b: the watermark signature travels with the session so a restart keeps a verifiable mark.
        sb.append("wm_sig=").append(watermarkSignature == null ? "" : watermarkSignature).append('\n');
        byte[] sealed = aesGcmSeal(key, sb.toString().getBytes(StandardCharsets.UTF_8));
        Files.createDirectories(stateFile.getParent());
        Files.write(stateFile, sealed);
    }

    /**
     * Loads {@code ck.bin} into the DLL. A false result is terminal for the caller: it means the
     * sealed key belongs to another Windows user/machine, is truncated, or is missing, i.e. the
     * session cannot be renewed and the user must re-activate.
     */
    private boolean loadClientKey() {
        if (clientKeyFile == null || !Files.isRegularFile(clientKeyFile)) {
            diag("client key file missing: " + clientKeyFile);
            return false;
        }
        try {
            boolean ok = ChimeraRuntime.nativeUnsealClientKey(Files.readAllBytes(clientKeyFile));
            if (!ok) {
                // Red team round 4 (live attack): the DLL refuses to unseal for two completely
                // different reasons - the sealed blob does not belong to this Windows user/machine,
                // or the integrity/anti-debug check refused before even looking at it. Both used to
                // be logged as "client key unavailable", so when a hardware breakpoint was armed the
                // log blamed ck.bin and sent the investigation the wrong way. vmpCrc=1 together with
                // an existing file means the refusal was integrity-side, not file-side.
                diag("client key unseal REFUSED (vmpCrc=" + ChimeraRuntime.vmpImageCrc()
                        + " poisoned=" + ChimeraRuntime.isPoisonedBridge()
                        + " file=" + clientKeyFile
                        + ") - vmpCrc=1 means the DLL refused on integrity/anti-debug grounds, "
                        + "not because the file is unreadable");
                return false;
            }
            diag("client key unseal ok file=" + clientKeyFile);
            return true;
        } catch (Throwable failure) {
            diag("client key unseal failed " + failure);
            return false;
        }
    }

    /** Asks the DLL for the DPAPI blob of the current key pair and writes it to {@code ck.bin}. */
    private boolean persistClientKey() {
        if (clientKeyFile == null) {
            return false;
        }
        try {
            byte[] sealed = ChimeraRuntime.nativeSealClientKey();
            if (sealed == null || sealed.length == 0) {
                diag("client key seal returned nothing");
                return false;
            }
            Path parent = clientKeyFile.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.write(clientKeyFile, sealed);
            return true;
        } catch (Throwable failure) {
            diag("client key persist failed " + failure);
            return false;
        }
    }

    /** The DPAPI-sealed client key blob on disk, or {@code null} when it is unavailable. */
    private byte[] clientKeyBlob() {
        if (clientKeyFile == null || !Files.isRegularFile(clientKeyFile)) {
            return null;
        }
        try {
            byte[] blob = Files.readAllBytes(clientKeyFile);
            return blob.length == 0 ? null : blob;
        } catch (Throwable ignored) {
            return null;
        }
    }

    /**
     * AES key for {@code license.dat}.
     *
     * <p>P0-3: this used to be {@code sha256(hwid + "|chimera-v4-state")}, which any attacker can
     * compute from public machine data. It now mixes in the DPAPI-sealed client key blob, which
     * only this Windows user (on this machine) can produce, so a copied state file is undecryptable
     * and no offline hwid guess reconstructs the key.</p>
     *
     * @return the key, or {@code null} when no sealed client key is available (fail closed)
     */
    private byte[] stateKey() throws Exception {
        byte[] seed = clientKeyBlob();
        if (seed == null) {
            return null;
        }
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(seed);
        digest.update((byte) '|');
        digest.update(hwid.getBytes(StandardCharsets.UTF_8));
        return digest.digest();
    }

    /** Unwraps the ECDH-sealed ResourceKey (shared with tests). */
    static byte[] unwrapResourceKey(java.security.PrivateKey clientPrivate, byte[] serverPubRaw,
                                    String clientNonce, String account, String hwid,
                                    byte[] envelope) throws Exception {
        byte[] shared = ecdh(clientPrivate, x25519Public(serverPubRaw));
        byte[] wrapKey = hkdf(shared, clientNonce.getBytes(StandardCharsets.UTF_8),
                "chimera/v1/v4/ck".getBytes(StandardCharsets.UTF_8), 32);
        byte[] aad = ("chimera/v1/v4/ck|" + account + "|" + hwid)
                .getBytes(StandardCharsets.UTF_8);
        return aesGcmOpen(wrapKey, envelope, aad);
    }

    private boolean verifySignature(Map<String, String> fields) throws Exception {
        return verifyActivateSignature(pinnedPub, fields);
    }

    /** Verifies the activate-response signature (shared with tests). */
    static boolean verifyActivateSignature(byte[] pinnedRaw, Map<String, String> fields)
            throws Exception {
        // Server canonical: domain, decimal version, then the 12 response fields (no duplicate "v").
        String[] order = {"account", "hwid", "client_ephemeral_pub", "client_nonce",
                "server_ephemeral_pub", "server_nonce", "token", "sequence", "issued_at",
                "expires_at", "server_time", "resource_ck"};
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(buffer);
        transcript(out, ACTIVATE_DOMAIN);
        transcript(out, "4");
        for (String field : order) {
            transcript(out, fields.getOrDefault(field, ""));
        }
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(ed25519Public(pinnedRaw));
        verifier.update(buffer.toByteArray());
        return verifier.verify(Base64.getDecoder().decode(fields.get("signature")));
    }

    private static void transcript(DataOutputStream out, String value) throws Exception {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        out.writeInt(bytes.length);
        out.write(bytes);
    }

    private static PublicKey ed25519Public(byte[] raw) throws Exception {
        byte[] encoded = new byte[ED25519_X509_PREFIX.length + raw.length];
        System.arraycopy(ED25519_X509_PREFIX, 0, encoded, 0, ED25519_X509_PREFIX.length);
        System.arraycopy(raw, 0, encoded, ED25519_X509_PREFIX.length, raw.length);
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(encoded));
    }

    private static PublicKey x25519Public(byte[] raw) throws Exception {
        byte[] encoded = new byte[X25519_X509_PREFIX.length + raw.length];
        System.arraycopy(X25519_X509_PREFIX, 0, encoded, 0, X25519_X509_PREFIX.length);
        System.arraycopy(raw, 0, encoded, X25519_X509_PREFIX.length, raw.length);
        return KeyFactory.getInstance("X25519").generatePublic(new X509EncodedKeySpec(encoded));
    }

    private static byte[] extractRaw(PublicKey key) {
        byte[] encoded = key.getEncoded();
        return Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
    }

    private static byte[] ecdh(java.security.PrivateKey privateKey, PublicKey peer) throws Exception {
        KeyAgreement agreement = KeyAgreement.getInstance("X25519");
        agreement.init(privateKey);
        agreement.doPhase(peer, true);
        return agreement.generateSecret();
    }

    static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int length) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt.length == 0 ? new byte[32] : salt, "HmacSHA256"));
        byte[] prk = mac.doFinal(ikm);
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] previous = new byte[0];
        int counter = 1;
        while (out.size() < length) {
            mac.update(previous);
            mac.update(info);
            mac.update((byte) counter++);
            previous = mac.doFinal();
            out.write(previous);
        }
        return Arrays.copyOf(out.toByteArray(), length);
    }

    private static byte[] aesGcmOpen(byte[] key, byte[] envelope, byte[] aad) throws Exception {
        if (envelope.length < 12 + 16) {
            return null;
        }
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, envelope, 0, 12));
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        try {
            return cipher.doFinal(envelope, 12, envelope.length - 12);
        } catch (Exception badTag) {
            return null;
        }
    }

    private static byte[] aesGcmSeal(byte[] key, byte[] plain) throws Exception {
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, nonce));
        byte[] sealed = cipher.doFinal(plain);
        byte[] out = new byte[nonce.length + sealed.length];
        System.arraycopy(nonce, 0, out, 0, nonce.length);
        System.arraycopy(sealed, 0, out, nonce.length, sealed.length);
        return out;
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    private static String toJson(Map<String, Object> values) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> entry : values.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append('"').append(entry.getKey()).append("\":");
            Object value = entry.getValue();
            if (value instanceof Number) {
                sb.append(value);
            } else {
                sb.append('"').append(escape(String.valueOf(value))).append('"');
            }
        }
        return sb.append('}').toString();
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    /**
     * Parses the flat v4 response object into its field strings.
     *
     * <p>String values must be <b>unescaped</b>: the server signs the raw field text and then
     * JSON-escapes it on the wire, so a value containing {@code \}, {@code "} or a control
     * character arrives with escape sequences. Keeping them literal made the rebuilt canonical
     * transcript differ from the signed one, i.e. a valid response failed the native Ed25519 check
     * (E_SIGNATURE / native finish -7).</p>
     */
    static Map<String, String> parseFlatJson(String json) {
        Map<String, String> fields = new LinkedHashMap<>();
        int i = 0;
        while (i < json.length()) {
            int keyStart = json.indexOf('"', i);
            if (keyStart < 0) {
                break;
            }
            StringBuilder key = new StringBuilder();
            int afterKey = readString(json, keyStart, key);
            if (afterKey < 0) {
                break;
            }
            int colon = json.indexOf(':', afterKey);
            if (colon < 0) {
                break;
            }
            int valueStart = colon + 1;
            while (valueStart < json.length() && Character.isWhitespace(json.charAt(valueStart))) {
                valueStart++;
            }
            if (valueStart >= json.length()) {
                break;
            }
            if (json.charAt(valueStart) == '"') {
                StringBuilder value = new StringBuilder();
                int afterValue = readString(json, valueStart, value);
                if (afterValue < 0) {
                    break;
                }
                fields.put(key.toString(), value.toString());
                i = afterValue;
            } else {
                int valueEnd = valueStart;
                while (valueEnd < json.length() && ",}".indexOf(json.charAt(valueEnd)) < 0) {
                    valueEnd++;
                }
                fields.put(key.toString(), json.substring(valueStart, valueEnd).trim());
                i = valueEnd;
            }
        }
        return fields;
    }

    /** Reads one JSON string starting at {@code start} (a quote); appends the unescaped text. */
    private static int readString(String json, int start, StringBuilder out) {
        int i = start + 1;
        while (i < json.length()) {
            char c = json.charAt(i);
            if (c == '"') {
                return i + 1;
            }
            if (c != '\\') {
                out.append(c);
                i++;
                continue;
            }
            if (i + 1 >= json.length()) {
                return -1;
            }
            char escape = json.charAt(i + 1);
            switch (escape) {
                case '"': out.append('"'); i += 2; break;
                case '\\': out.append('\\'); i += 2; break;
                case '/': out.append('/'); i += 2; break;
                case 'b': out.append('\b'); i += 2; break;
                case 'f': out.append('\f'); i += 2; break;
                case 'n': out.append('\n'); i += 2; break;
                case 'r': out.append('\r'); i += 2; break;
                case 't': out.append('\t'); i += 2; break;
                case 'u': {
                    if (i + 6 > json.length()) {
                        return -1;
                    }
                    try {
                        out.append((char) Integer.parseInt(json.substring(i + 2, i + 6), 16));
                    } catch (NumberFormatException e) {
                        return -1;
                    }
                    i += 6;
                    break;
                }
                default:
                    out.append(escape);
                    i += 2;
                    break;
            }
        }
        return -1;
    }

    private static String post(String url, String body) {
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) new URL(url).openConnection();
            connection.setConnectTimeout(8000);
            connection.setReadTimeout(8000);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setDoOutput(true);
            connection.getOutputStream().write(body.getBytes(StandardCharsets.UTF_8));
            int code = connection.getResponseCode();
            InputStream stream = code >= 400
                    ? connection.getErrorStream() : connection.getInputStream();
            return stream == null ? null
                    : new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        } catch (Throwable failure) {
            return null;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private static long parseLong(String value) {
        try {
            return Long.parseLong(value == null ? "0" : value.trim());
        } catch (NumberFormatException ignored) {
            return 0L;
        }
    }


    /**
     * Onboarding (2026-10-22): registers an account against the hardware slot the operator
     * pre-registered.
     *
     * <p>The request carries this machine's HWID; the server only accepts it if that exact id was
     * reserved and not yet claimed, so the player never needs an invite code and the operator never
     * creates the account.</p>
     *
     * @return {@code null} on success, otherwise a player-facing message
     */
    public String register(String account, char[] password) {
        try {
            Map<String, Object> request = new LinkedHashMap<>();
            request.put("account", account);
            request.put("password", new String(password));
            request.put("hwid", hwid);
            String body = post(server + V4_REGISTER, toJson(request));
            if (body == null) {
                return "网络错误：注册请求没有响应";
            }
            Map<String, String> fields = parseFlatJson(body);
            String error = fields.get("error");
            if (error != null) {
                return describeRegisterError(error);
            }
            return fields.containsKey("status") ? null : "注册响应异常";
        } catch (Throwable failure) {
            return "注册失败：" + failure.getMessage();
        }
    }

    private static String describeRegisterError(String code) {
        return switch (code) {
            case "E_HWID_NOT_RESERVED" -> "本机未在后台登记，请把 HWID 发给客服";
            case "E_HWID_CLAIMED" -> "本机已经注册过账号，请直接登录";
            case "E_ACCOUNT_EXISTS" -> "账号已存在，请换一个";
            case "E_RATE_LIMIT" -> "尝试过于频繁，请稍后再试";
            case "E_BAD_REQUEST" -> "账号或密码不符合要求（密码至少 6 位）";
            default -> "注册失败：" + code;
        };
    }

    /**
     * Maps a server error code to a panel status.
     *
     * <p>Red team round 4 (source audit): only five codes were recognised and everything else fell
     * through to {@code E_NETWORK}, so a banned account, a wrong password and a device mismatch all
     * told the user to "check your connection and retry" - the three cases where retrying can never
     * work. The split is now: no response at all = network; a response with an unrecognised code =
     * the server rejected us (terminal); known codes keep their specific meaning.</p>
     */
    static ChimeraActivationPanel.Status mapError(String code) {
        if (code == null) {
            return ChimeraActivationPanel.Status.E_NETWORK;
        }
        return switch (code) {
            case "E_EXPIRED" -> ChimeraActivationPanel.Status.E_EXPIRED;
            case "E_CLOCK_ROLLBACK" -> ChimeraActivationPanel.Status.E_CLOCK_ROLLBACK;
            case "E_SIGNATURE" -> ChimeraActivationPanel.Status.E_SIGNATURE;
            case "E_STATE" -> ChimeraActivationPanel.Status.E_STATE;
            // Wrong password / unknown account. The server deliberately does not distinguish them.
            case "E_AUTH", "E_CREDENTIALS" -> ChimeraActivationPanel.Status.E_CREDENTIALS;
            // The machine is not the one this licence is bound to, or the device limit is reached.
            case "E_HWID", "E_HWID_MISMATCH", "E_DEVICE_KEY_MISMATCH", "E_BINDING",
                 "E_DEVICE_LIMIT" -> ChimeraActivationPanel.Status.E_HWID;
            // Banned / revoked / deleted: nothing the user can retry.
            case "E_REVOKED", "E_ACCOUNT_NOT_FOUND" -> ChimeraActivationPanel.Status.E_REVOKED;
            // Throttled or a replayed request: transient, but not a connectivity problem.
            case "E_RATE_LIMIT", "E_REPLAY", "E_SEQUENCE" -> ChimeraActivationPanel.Status.E_REJECTED;
            default -> ChimeraActivationPanel.Status.E_REJECTED;
        };
    }
}
