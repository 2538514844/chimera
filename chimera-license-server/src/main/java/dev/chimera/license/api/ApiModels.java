package dev.chimera.license.api;

/**
 * Wire models of docs/AUTH-V2-PROTOCOL.md. Record component names are the JSON field names
 * (snake_case on purpose: the client rebuilds the canonical transcript from these exact strings).
 */
public final class ApiModels {

    private ApiModels() {
    }

    public record ActivateRequest(String account, String password, String hwid,
                                  String client_ephemeral_pub) {
    }

    public record ActivateResponse(String server_nonce, String server_ephemeral_pub,
                                   String wrapped_ck, String resource_ck, long expires_at,
                                   long sequence, long issued_at, String token, String account,
                                   long server_time, String signature) {
    }

    public record HeartbeatRequest(String token) {
    }

    public record HeartbeatResponse(String server_nonce, long expires_at, long sequence,
                                    long issued_at, long server_time, String signature) {
    }

    public record ErrorResponse(String error) {
    }

    /** Admin/build endpoint response: ResourceKey for the build pipeline (never the MasterKey). */
    public record BuildResourceKeyResponse(String resource_key, String fingerprint) {
    }

    // ------------------------------------------------------------------ v4 wire models

    /** v4 activation request: password stays out of the signed transcript. */
    public record ActivateV4Request(int v, String account, String password, String hwid,
                                    String client_ephemeral_pub, String client_nonce) {
    }

    /**
     * v4 activation response. Field order is the canonical transcript order; {@code resource_ck}
     * may be empty but is always signed.
     *
     * <p>#17 (2026-10-22): {@code license_id} is the account's stable licence identifier and
     * {@code client_ip} is the address the server saw. Both are appended to the signed transcript
     * (see {@code AuthTranscriptV4}), so the client may rely on them.</p>
     *
     * <p>#19b: {@code wm_sig} is an Ed25519 signature over {@code "chimera-wm-v1|licenseId|account"}.
     * It deliberately does <b>not</b> participate in the transcript - it is self-authenticating, so
     * it needs no second signature, and leaving the transcript alone keeps the protocol stable. The
     * client embeds it in the watermark payload so the operator can tell a genuine payload from one
     * forged with somebody else's licence id.</p>
     */
    public record ActivateV4Response(int v, String account, String hwid,
                                     String client_ephemeral_pub, String client_nonce,
                                     String server_ephemeral_pub, String server_nonce, String token,
                                     long sequence, long issued_at, long expires_at,
                                     long server_time, String resource_ck, String license_id,
                                     String client_ip, String wm_sig, String signature) {
    }

    /** v4 heartbeat request: binds the presented token, HWID and the client's sequence/nonce. */
    public record HeartbeatV4Request(int v, String hwid, String token, String client_nonce,
                                     long sequence, String client_ephemeral_pub) {
    }

    /** v4 heartbeat response: {@code token} is the rotated token, never the presented one. */
    public record HeartbeatV4Response(int v, String hwid, String client_nonce, String token,
                                      long sequence, String server_nonce, long issued_at,
                                      long expires_at, long server_time, String resource_ck,
                                      String server_ephemeral_pub, String license_id,
                                      String client_ip, String wm_sig, String signature) {
    }
}
