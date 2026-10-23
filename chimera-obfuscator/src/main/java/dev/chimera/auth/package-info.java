/**
 * S7 auth protocol v4 pure-logic components (client side).
 *
 * <h2>Wire contract</h2>
 * Activation request JSON: {@code v=4, account, password, hwid, client_ephemeral_pub, client_nonce}.
 * Activation response JSON: {@code v, account, hwid, client_ephemeral_pub, client_nonce,
 * server_ephemeral_pub, server_nonce, token, sequence, issued_at, expires_at, server_time,
 * resource_ck, signature}. Heartbeat request: {@code v, hwid, token, client_nonce, sequence}.
 * Heartbeat response: {@code v, hwid, client_nonce, token(new), sequence, server_nonce, issued_at,
 * expires_at, server_time, signature}.
 *
 * <h2>Canonical bytes</h2>
 * Signatures are over a domain-separated length-prefixed binary transcript (no JSON escaping
 * ambiguity): {@code for each field: u32be(len) || utf8(field)}, starting with a per-message domain
 * string and then the decimal version. See {@link dev.chimera.auth.AuthTranscriptV4}. Activation
 * response canonical includes the four request-binding fields (account, hwid,
 * client_ephemeral_pub, client_nonce) so a TLS-terminating MITM cannot swap the client key.
 * Heartbeat response canonical binds the presented token via its SHA-256.
 *
 * <h2>Wiring (Lead, ChimeraRuntime)</h2>
 * <ol>
 *   <li>Create one {@link dev.chimera.auth.AuthProtocolV4} with a pinned Ed25519 public key, an
 *       {@link dev.chimera.auth.EncryptedFileSequenceStore} (state dir from config) and optionally
 *       a native {@link dev.chimera.auth.SignatureVerifier}.</li>
 *   <li>{@code newActivation(account, hwid, clientEpk)} -> serialize fields + password -> POST
 *       /api/v1/license/activate -> parse fields into {@link dev.chimera.auth.ActivationResponseV4}
 *       -> {@code verifyActivate} -> only then unwrap wrapped_ck/resource_ck in native.</li>
 *   <li>{@code newHeartbeat(session)} -> POST /api/v1/license/heartbeat -> parse ->
 *       {@code verifyHeartbeat} -> persist/rotate token and install new server nonce.</li>
 *   <li>Any {@link dev.chimera.auth.AuthProtocolException}: markPoison(), never throw to game code.</li>
 * </ol>
 * The component deliberately performs no HTTP, JSON parsing, ECDH, AES-GCM unwrap, or key
 * installation; those stay in ChimeraRuntime/native. It does not retain passwords.
 */
package dev.chimera.auth;
