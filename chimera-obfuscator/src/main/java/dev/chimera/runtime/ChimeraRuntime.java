package dev.chimera.runtime;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.invoke.CallSite;
import java.lang.invoke.ConstantCallSite;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.invoke.VarHandle;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Method;
import java.nio.ByteOrder;
import java.util.function.LongSupplier;
import java.nio.charset.StandardCharsets;
import java.net.HttpURLConnection;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Self-contained runtime injected into the protected jar (java.base only, no nested classes,
 * no lambdas). It decrypts the encrypted string table, bootstraps hidden-class method fragments
 * and verifies the class integrity manifest.
 *
 * <p>Build-time counterpart: {@code Crypto}, {@code TransformContext.encodeStringTable()},
 * {@code FragmentTransformer} and {@code ManifestBuilder}. The binary formats below must stay in
 * sync with those classes.</p>
 */
public final class ChimeraRuntime implements Runnable {

    /** "CHV1" - environment record. */
    private static final int ENV_MAGIC = 0x43485631;
    /** Environment flags bit 0: dev build (diagnostic overrides honoured). */
    private static final int ENV_FLAG_DEV = 1;
    /** "CHS1" - string table. */
    private static final int STRING_TABLE_MAGIC = 0x43485331;
    /** "CHK1" - single hidden-class chunk. */
    private static final int CHUNK_MAGIC = 0x43484B31;
    /** "CHB1" - per-chunk build-time hash record (B6). */
    private static final int CHUNK_HASH_MAGIC = 0x43484231;
    /** KI-28: outer sealed chunk-hash record ("CHB2"). */
    private static final int CHUNK_HASH_SEALED_MAGIC = 0x43484232;
    private static final int CHUNK_HASH_LENGTH = 32;
    /** Sealed chunk-hash: magic(4) + nonce(12) + AES-GCM(44-byte record)[60]. */
    private static final int CHUNK_HASH_SEALED_LENGTH = 4 + 12 + 44 + 16;

    /** KI-28 sealed manifest digest: nonce(12) + AES-GCM(sha256(manifest))[48]. */
    private static final int MANIFEST_NONCE_LENGTH = 12;
    private static final int MANIFEST_SEALED_MAC_LENGTH = MANIFEST_NONCE_LENGTH + 32 + 16;
    private static final String MANIFEST_KIND = "manifest";
    private static final int MANIFEST_ID = 0;
    private static final String MANIFEST_AAD = "manifest/0";

    /** C-06 sealed string-table digest: nonce(12) + AES-GCM(sha256(table))[48]. */
    public static final String STRINGS_KIND = "strings";
    public static final int STRINGS_ID = 0;
    public static final String STRINGS_AAD = "strings/0";
    private static final int STRINGS_SEALED_MAC_LENGTH = 12 + 32 + 16;

    private static final String KEY_PROPERTY = "chimera.contentKey";
    private static final String KEY_ENV = "CHIMERA_CONTENT_KEY";
    /** KI-28: the product ResourceKey used by the build pipeline (""dev/no-handle"" path only). */
    private static final String RESOURCE_KEY_PROPERTY = "chimera.resourceKey";
    private static final String RESOURCE_KEY_ENV = "CHIMERA_RESOURCE_KEY";
    private static final String RESOURCE_KEY_ENV_HEX = "CHIMERA_RESOURCE_KEY_HEX";
    private static final String VERIFY_PROPERTY = "chimera.verify";

    private static final int KEY_LENGTH = 32;
    private static final int NONCE_LENGTH = 12;
    private static final int MAX_BLOCK_LENGTH = 64 * 1024 * 1024;
    private static final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();

    /** Raw legacy content-key material (hex bytes or SHA-256 of the passphrase), dev only. */
    private static volatile byte[] contentKeyMaterial;
    /**
     * KI-28: build-time ResourceKey for jars without a native SessionHandle (dev/no-native path).
     * In authorized mode installNativeHandle clears it; C++ op9 decrypts with its own copy.
     */
    private static volatile byte[] resourceKeyMaterial;
    /** Nonzero only after a native SessionHandle was installed by the license handshake. */
    private static volatile long nativeSessionHandle;
    private static final byte NATIVE_OP_DERIVE_ITEM = 1;
    private static final byte NATIVE_OP_HMAC = 2;
    private static final byte NATIVE_OP_SESSION_KEY = 3;
    private static final byte NATIVE_OP_DYNAMIC_KEY = 4;
    private static final byte NATIVE_OP_CANARY = 5;
    /**
     * Night task: resource decryption inside native code (op 9 = DECRYPT_DATA, confirmed by
     * native-pipeline; op6/7/8 are reserved for B7 VM/VERIFY_DECISION/AOT diff).
     * Contract: kind/id/salt/nonce/aad/ciphertext -> plaintext, empty on failure.
     */
    private static final byte NATIVE_OP_DECRYPT_DATA = 9;

    private static volatile byte[] envSalt;
    private static volatile String buildId;
    private static volatile boolean envLoaded;

    private static volatile byte[] kek;
    /**
     * C-06: the string table is kept encrypted in memory and decrypted on demand into a small
     * fixed-size slot cache. A dump can no longer recover the whole plaintext table at once, and
     * startup does not decrypt strings the program never uses.
     */
    private static final int STRING_CACHE_SLOTS = 512;
    private static final String[] stringCacheValues = new String[STRING_CACHE_SLOTS];
    private static final int[] stringCacheIds = new int[STRING_CACHE_SLOTS];
    private static volatile Map<Integer, byte[][]> stringIndex;
    private static volatile boolean stringIndexLoaded;

    static {
        java.util.Arrays.fill(stringCacheIds, -1);
        try {
            // G7: the preLaunch gate resolves a real license through this backend.
            ChimeraPreLaunch.installBackend(new ChimeraLicenseBackend());
        } catch (Throwable ignored) {
            // Without a gate class the runtime keeps its normal (already licensed) behaviour.
        }
    }
    private static volatile boolean integrityChecked;
    /** Set when the key/integrity state is invalid; all entanglement masks become poisoned. */
    private static volatile boolean poisoned;
    /** Non-zero mask returned to entangled arithmetic once the key state is invalid. */
    private static final long POISON_MASK = 0x9E3779B97F4A7C15L;
    /** Non-zero dynamic key returned once the key state is invalid. */
    private static final long POISON_KEY = 0xDEADBEEFCAFEBABEL;

    // --- Task 1: server nonce bound session state ---
    private static volatile long serverNonce;
    private static volatile byte[] sessionKey;
    private static volatile long sessionEpoch;
    private static volatile long cachedSessionStamp;
    private static volatile boolean sessionStampReady;

    // --- module 4: license handshake (wire contract: docs/AUTH-V2-PROTOCOL.md) ---
    private static final String AUTH_RESOURCE = "/chimera/auth.dat";
    private static final String AUTH_SERVER_PROPERTY = "chimera.auth.server";
    private static final String AUTH_PUBKEY_PROPERTY = "chimera.auth.pubkey";
    private static final String AUTH_AUTO_HEARTBEAT_PROPERTY = "chimera.auth.autoHeartbeat";
    private static final String AUTH_PIN_PROPERTY = "chimera.auth.pin";
    private static final String AUTH_ALLOW_INSECURE_PROPERTY = "chimera.auth.allowInsecure";
    private static final String AUTH_CLOCK_SKEW_PROPERTY = "chimera.auth.clockSkewSeconds";
    private static final int AUTH_NONCE_LENGTH = 16;
    // "Server gone = unusable" (user requirement 2026-10-22): the previous 300s x 3 failures left a
    // 15-minute window in which a player could keep using the client after losing connectivity.
    // 60s x 2 bounds that window to ~2 minutes while still tolerating a single dropped packet.
    private static final long DEFAULT_HEARTBEAT_MS = 60_000L;
    /** Hard ceiling regardless of what chimera/auth.dat asks for (see the heartbeatMs parser). */
    private static final long MAX_HEARTBEAT_MS = 60_000L;
    private static final int HEARTBEAT_FAILURES_BEFORE_POISON = 2;
    private static final long DEFAULT_CLOCK_SKEW_SECONDS = 300L;
    private static final ChimeraRuntime AUTH_THREAD_BODY = new ChimeraRuntime();

    private static volatile byte[] serverNonceBytes;
    private static volatile String authServer;
    private static volatile String authServerPubkey;
    private static volatile String authServerPin;
    private static volatile boolean authAllowInsecure;
    private static volatile long authClockSkewSeconds = DEFAULT_CLOCK_SKEW_SECONDS;
    private static volatile long authLastSequence;
    private static volatile long authLastIssuedAt;
    private static volatile long authHeartbeatMs = DEFAULT_HEARTBEAT_MS;
    private static volatile String authToken;
    private static volatile long authExpiresAt;
    private static volatile Thread authHeartbeatThread;
    private static volatile int authHeartbeatFailures;
    // B7-pre/KI-26: credentials of the last successful activation, used only for the
    // "handle expired -> re-authenticate" retry path. Memory only, wiped on poison/logout.
    private static volatile String authCachedAccount;
    private static volatile String authCachedPassword;
    private static volatile String authCachedHwid;
    private static volatile boolean refreshInProgress;
    private static volatile long lastRefreshAttemptNanos;
    private static volatile long lastCanaryCheckNanos;
    private static final long AUTH_REFRESH_BACKOFF_NANOS = 3_000_000_000L;
    private static final long CANARY_CHECK_INTERVAL_NANOS = 1_000_000_000L;

    // --- Task 2: timing channel + memory wipe ---
    // --- B4: sliding-window pause detection (no ThreadMXBean / no 10 ms CPU threshold) ---
    // A sample is one fragment bootstrap. Slow = elapsed > 100 ms (QPC monotonic clock).
    // Poison only when the last 8 samples contain >=5 slow samples OR >=3 consecutive slow
    // samples; a detected Java agent/JDWP/Frida lowers the requirement to one slow sample.
    private static final int DEFAULT_WINDOW_THRESHOLD_MS = 100;
    private static final int DEFAULT_WINDOW_CONSECUTIVE = 3;
    private static final int DEFAULT_WINDOW_SIZE = 8;
    private static final int DEFAULT_WINDOW_SLOW_LIMIT = 5;
    private static volatile int timingSuspicionCount;      // total slow samples
    private static volatile int consecutiveSlowBootstraps; // current consecutive slow streak
    private static volatile int timingWindowBits;          // newest sample in bit 0
    private static volatile int timingWindowSamples;
    private static volatile boolean timingAgentDetected;
    private static volatile boolean timingAgentChecked;
    private static volatile String timingAgentSignalSource;
    private static volatile LongSupplier timingSource;     // injected monotonic clock (tests)
    private static volatile LongSupplier wallTimingSource; // fallback clock injection (tests)
    private static volatile boolean nativeQpcUnavailable;
    private static volatile boolean b6PartialLogged;
    private static volatile long lastBootstrapNanos;
    private static volatile boolean lastWipeZeroed;
    private static volatile long wipeCount;
    private static volatile boolean unsafeInitialized;
    private static volatile boolean unsafeAvailable;
    private static volatile long unsafeArrayBase;
    private static volatile int unsafeArrayScale;
    private static volatile MethodHandle unsafePutByte;
    private static volatile MethodHandle unsafeStoreFence;
    private static volatile VarHandle byteView;

    // --- M8: all asymmetric crypto (Ed25519/X25519/AES-GCM unwrap) lives in native code ---
    private static final String NATIVE_AUTH_PATH_PROPERTY = "chimera.native.auth.path";
    private static volatile boolean nativeAuthLoaded;

    static {
        loadNativeAuth();
    }

    private static void loadNativeAuth() {
        String explicit = System.getProperty(NATIVE_AUTH_PATH_PROPERTY);
        if (explicit != null && !explicit.isBlank()) {
            try {
                System.load(explicit);
                nativeAuthLoaded = true;
                applyNativeAntiDebugMode();
                return;
            } catch (Throwable ignored) {
                // fall back to the library path
            }
        }
        try {
            System.loadLibrary("chimera_auth");
            nativeAuthLoaded = true;
            applyNativeAntiDebugMode();
        } catch (Throwable ignored) {
            nativeAuthLoaded = false;
        }
    }

    /**
     * Native anti-debug policy (M7 anti-false-positive): 0 = telemetry (default), 1 = strict
     * (poison on debugger signals unless a known security product is loaded), 2 = off. Explicit
     * Frida modules always poison, in every mode except off.
     */
    public static native void nativeSetAntiDebugMode(int mode);

    /** Number of native anti-debug signals observed so far (diagnostics/telemetry). */
    public static native int nativeAntiDebugSignalCount();

    /**
     * B4: monotonic high-resolution clock (Windows QueryPerformanceCounter converted to ns since
     * boot). Returns -1 when unavailable; Java then falls back to System.nanoTime.
     */
    public static native long nativeQpcNanos();

    /** B4 fallback wall clock (GetTickCount64 * 1e6, milliseconds resolution). */
    public static native long nativeWallClockNanos();

    /** B6: 1 when JVMTI GetBytecodes is available for post-define byte verification. */
    public static native int nativeJvmtiAvailable();

    /**
     * B6: hashes the classfile bytes the VM actually installed for a hidden class (JVMTI
     * GetBytecodes) and compares them with {@code expectedSha256}. 1 = match, 0 = mismatch
     * (tampered), -1 = JVMTI unavailable/error. Never returns class bytes to Java.
     */
    public static native int nativeHiddenClassBytesMatch(Class<?> hiddenClass, byte[] expectedSha256);

    // ---------------------------------------------------------------- S5 payload overlay
    // Exported by chimera_auth.cpp; the Java loader (ChimeraPayloadLoader) resolves these
    // reflectively so a missing native surface fails closed instead of crashing the JVM.

    // ---------------------------------------------------------------- S5 hidden class / probe
    /** v4: native keeps the ephemeral X25519 private key; Java receives pub||nonce in out[48]. */
    public static native int nativeAuthV4Begin(byte[] out);

    /** v4: verifies the signed response and unwraps the ResourceKey into a native handle. */
    public static native long nativeAuthV4Finish(byte[] canonical, byte[] signature,
            byte[] serverPub, byte[] envelope, byte[] account, byte[] hwid);

    /** v4 heartbeat: same verification/unwrap path, bound to the client nonce only. */
    public static native long nativeAuthV4HeartbeatFinish(byte[] canonical, byte[] signature,
            byte[] serverPub, byte[] envelope, byte[] account, byte[] hwid);

    /** v4: 1 = handle valid, 0 = missing/expired/poisoned. */
    public static native int nativeAuthV4Status(long handle);

    /**
     * v4: returns the current client X25519 private key sealed with DPAPI (current Windows user
     * scope) as an opaque blob, or {@code null} when no key is available. Java may persist and
     * hand the blob back, but can neither read the key nor mint a blob for another key.
     */
    public static native byte[] nativeSealClientKey();

    /**
     * v4: unseals a blob from {@link #nativeSealClientKey()} into the native key slot.
     * {@code false} means the blob belongs to another Windows user/machine or was tampered with;
     * callers must treat that as "re-activation required" and must not ask for a fresh key.
     */
    public static native boolean nativeUnsealClientKey(byte[] sealed);

    /** B1: registers sunk native method bodies (called from preLaunch, not JNI_OnLoad). */
    public static native int nativeRegisterSinkMethods();

    /** Early-load tracing marker (trace builds only). */
    public static native void nativeTraceMark();

    // C-4: nativeDefineClass / nativeRegisterHiddenClass / nativeIsHiddenClassRegistered were
    // removed. S1 keeps hidden entries under their real names so the Fabric class loader resolves
    // them; nothing defines classes through JNI any more (red line: never restore native DefineClass
    // hidden classes). The DLL no longer exports these symbols.

    /** Anti-dump probe bitmask (1 debugger, 2 known dump tool, 4 frida module, 8 test, 16 telemetry). */
    public static native int nativeAntiDumpProbe();

    /** Cumulative anti-dump hit counter. */
    public static native int nativeAntiDumpSignalCount();

    /** Provides the build envSalt the payload overlay key derivation needs (8..64 bytes). */
    public static native int nativeSetPayloadContext(byte[] envSalt);

    /** 1 = the loaded DLL carries a CHPY overlay, 0 = none. */
    public static native int nativePayloadAvailable();

    /** Ciphertext length of the overlay (0 when absent). */
    public static native long nativePayloadSize();

    /** SHA-256 of the overlay ciphertext (32 bytes) or empty when absent. */
    public static native byte[] nativePayloadDigest();

    /** Decrypts overlay bytes with the handle key; empty array on any failure. */
    public static native byte[] nativePayloadExtract(long handle, int offset, int length);

    private static void applyNativeAntiDebugMode() {
        try {
            // Phase 0 (C-02): release builds honour only the stricter direction; "off"/"false"
            // collapses back to the built-in default instead of disabling anti-debug.
            String value = DebugSwitches.property("chimera.native.antidebug");
            int mode = 0;
            if (value != null) {
                String trimmed = value.trim().toLowerCase(java.util.Locale.ROOT);
                if ("strict".equals(trimmed) || "enforce".equals(trimmed)) {
                    mode = 1;
                } else if ("off".equals(trimmed) || "false".equals(trimmed)
                        || "disabled".equals(trimmed)) {
                    mode = 2;
                }
            }
            if (mode == 2 && DebugSwitches.release()) mode = 0;
            nativeSetAntiDebugMode(mode);
        } catch (Throwable ignored) {
            // policy is best-effort; nativeVerifyAuth keeps its built-in default
        }
    }

    /** Generates the X25519 client key pair in native code; returns the raw 32-byte public key. */
    public static native byte[] nativeCreateClientKey();

    /** Sets the pinned Ed25519 server public key and account binding used by native crypto. */
    public static native void nativeSetAuthContext(byte[] serverPublicRaw32, byte[] accountUtf8);

    /**
     * True when this DLL carries a build-pinned licence-server key.
     *
     * <p>When pinned, {@link #nativeSetAuthContext} ignores whatever key the caller supplies, so
     * tests that run a synthetic server (signing with their own throwaway key) cannot obtain a
     * VALID handle. Those tests skip on this flag instead of asserting a behaviour the stronger
     * design no longer permits.</p>
     */
    public static native boolean nativeAuthPubkeyPinned();

    /**
     * Licence-server URL baked into this build, or {@code ""} when the build pinned none.
     *
     * <p>P2-1: when non-empty the runtime uses it and ignores {@code auth.dat}'s {@code server=}
     * line, so the file can no longer repoint the client at another endpoint.</p>
     */
    public static native String nativePinnedAuthServer();

    /** Native, cached VM check. Never trusts the CPUID hypervisor bit alone (VBS/Hyper-V). */
    public static native boolean nativeIsVirtualMachine();

    /**
     * #18: best-effort QQ number read from {@code Documents\Tencent Files\<digits>} with a bounded
     * read-only registry walk under {@code HKCU\Software\Tencent} as a fallback. Never scans process
     * memory. Empty string when unknown.
     */
    public static native String nativeQqHint();

    /**
     * #19: Base64 (X.509/SPKI) RSA public key baked into this build, or {@code ""} when the build
     * pinned none. The matching private key never leaves the licence server.
     */
    public static native String nativeWatermarkKey();

    /**
     * #18: the QQ number to embed in the per-licence watermark, or {@code ""} when it cannot be
     * determined.
     *
     * <p>Deliberately silent and non-interactive: the user is never asked to type a QQ number (a
     * value the user supplies is worthless for attribution) and a missing value stays missing. The
     * result is never logged.</p>
     */
    public static String qqHint() {
        if (!nativeAuthLoaded) {
            return "";
        }
        try {
            String value = nativeQqHint();
            if (value == null) {
                return "";
            }
            String trimmed = value.trim();
            return trimmed.matches("\\d{5,11}") ? trimmed : "";
        } catch (Throwable ignored) {
            return "";
        }
    }

    // ------------------------------------------------------- #19 per-licence watermark payload
    //
    // The attach agent injects one constant per class body (see WatermarkInjector). The constant is
    // RSA-encrypted with the operator's watermark public key, which is baked into this DLL, so the
    // value is opaque to the end user: only the holder of the private key can read whose build a
    // leaked copy came from. Attribution therefore survives a leaked jar even when the attacker
    // cannot be bothered to strip the watermark - and stripping it means patching every class.

    private static volatile String wmLicenseId;
    private static volatile String wmAccount;
    private static volatile String wmClientIp;
    private static volatile String wmSignature;
    private static volatile String wmPayload;

    /**
     * #19: records who is running this build. Called by the gate right after a session is
     * authorized; the values come from the signed activate/heartbeat response, so a modified client
     * cannot claim somebody else's licence id.
     */
    public static void setLicenseContext(String account, String licenseId, String clientIp) {
        setLicenseContext(account, licenseId, clientIp, "");
    }

    /** #19b: same, with the activation-time watermark signature (see ChimeraV4Session). */
    public static void setLicenseContext(String account, String licenseId, String clientIp,
                                         String signature) {
        wmAccount = account;
        wmLicenseId = licenseId;
        wmClientIp = clientIp;
        wmSignature = signature;
        wmPayload = null;
    }

    /**
     * #19: {@code CHMW1:} + Base64(RSA-OAEP-SHA256("licenseId|account|qq|ip|ts")), or {@code null}
     * when no watermark can be produced (no licence context, no baked key, no native module).
     *
     * <p>Computed once per process: the timestamp is the launch time, and every class in one
     * process must carry the same value or the payloads could not be correlated.</p>
     */
    public static String watermarkPayload() {
        String cached = wmPayload;
        if (cached != null) {
            return cached;
        }
        String licenseId = wmLicenseId;
        if (licenseId == null || licenseId.isBlank()) {
            return null;
        }
        try {
            String bakedKey = nativeAuthLoaded ? nativeWatermarkKey() : "";
            if (bakedKey == null || bakedKey.isEmpty()) {
                return null;
            }
            // Fields: licenseId|account|qq|ip|ts|wmSig. The last field is an Ed25519 signature the
            // server issued over "chimera-wm-v1|licenseId|account", so the forensic tool can prove
            // the payload was not forged with somebody else's licence id.
            String plain = licenseId + "|" + (wmAccount == null ? "" : wmAccount) + "|"
                    + qqHint() + "|" + (wmClientIp == null ? "" : wmClientIp) + "|"
                    + (System.currentTimeMillis() / 1000L) + "|"
                    + (wmSignature == null ? "" : wmSignature);
            java.security.PublicKey key = java.security.KeyFactory.getInstance("RSA")
                    .generatePublic(new java.security.spec.X509EncodedKeySpec(
                            java.util.Base64.getDecoder().decode(bakedKey)));
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(
                    "RSA/ECB/OAEPPadding");
            // Explicit OAEP parameters: the JDK's named OAEPWithSHA-256AndMGF1Padding transform
            // still uses MGF1-SHA1 on some providers, which silently breaks interoperability with
            // the extraction tool (and with openssl). Pin both digests.
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key,
                    new javax.crypto.spec.OAEPParameterSpec("SHA-256", "MGF1",
                            java.security.spec.MGF1ParameterSpec.SHA256,
                            javax.crypto.spec.PSource.PSpecified.DEFAULT));
            byte[] sealed = cipher.doFinal(plain.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            String payload = "CHMW1:" + java.util.Base64.getEncoder().encodeToString(sealed);
            wmPayload = payload;
            return payload;
        } catch (Throwable ignored) {
            return null;
        }
    }

    /**
     * True when this process runs inside a real virtual machine.
     *
     * <p>False when the native module is unavailable: an artifact that cannot answer is treated as
     * a normal machine, otherwise a DLL load failure would silently empty the mod for everyone.</p>
     */
    public static boolean isVirtualMachine() {
        if (!nativeAuthLoaded) {
            return false;
        }
        try {
            return nativeIsVirtualMachine();
        } catch (Throwable ignored) {
            return false;
        }
    }

    /**
     * #9: true when this DLL carries a build-pinned manifest HMAC key
     * ({@code -DCHIMERA_MANIFEST_KEY_HEX}). When false the artifact cannot authenticate
     * {@code chimera/manifest.dat} and the resource check says so in the diagnostic log instead of
     * pretending the resources are covered.
     */
    public static native boolean nativeManifestKeyPinned();

    /**
     * #9: HMAC-SHA256({@code manifestBytes}) under the build-pinned key, compared with {@code mac}
     * in constant time. Requires no session handle and no prior authorization: it is the check that
     * protects {@code chimera/auth.dat}, which the gate itself consumes. Always returns false on a
     * missing key, a wrong tag length or a native error.
     */
    public static native boolean nativeVerifyManifest(byte[] manifestBytes, byte[] mac);

    /**
     * A1/B1: native Ed25519 verify + X25519 unwrap + AES-GCM. Returns a 64-bit SessionHandle,
     * never key bytes. All paths (success/signature failure/poison) return the same long shape;
     * the 32-byte content key stays in the native handle table.
     */
    public static native long nativeVerifyAuth(byte[] serverResponseUtf8, byte[] hwidUtf8);

    /** B1: hash/state query for a handle. Same return shape for valid/invalid handles. */
    public static native long nativeCheckHandle(long handle);

    /**
     * B1: operation on a SessionHandle. Params are a byte opcode + payload:
     * 1 derive item key, 2 HMAC, 3 session key, 4 dynamic key, 5 canary (1/0).
     * Never returns the 32-byte product content key.
     */
    public static native byte[] nativeCompute(long handle, byte[] params);

    /**
     * P1-1: derives the CHENC1 class-body key from the ResourceKey held by the handle. Returns 32
     * bytes, or an empty array when the handle is missing, poisoned, expired or carries no
     * ResourceKey. Never returns the ResourceKey itself and never logs the result.
     */
    public static native byte[] nativeDeriveClassKey(long handle);

    /** B7-pre/KI-26: revokes one SessionHandle (wipes key material). 1 = revoked, 0 = unknown. */
    public static native int nativeRevokeHandle(long handle);

    /** B7-pre/KI-26: revokes every SessionHandle (logout / key purge). Returns slots wiped. */
    public static native int nativeRevokeAllHandles();

    /** B7-pre/KI-26: current SessionHandle idle TTL in milliseconds (spec window 5-15 min). */
    public static native long nativeHandleTtlMs();

    /** B7-pre/KI-26: clamps and sets the idle TTL; returns the effective value. */
    public static native long nativeSetHandleTtlMs(long ttlMs);

    /** QA-only: backdates a handle so the TTL expiry path runs without waiting ten minutes. */
    public static native int nativeExpireHandleForTest(long handle);

    /** 1 = dev/test DLL (QA hooks present, short TTL allowed), 0 = release DLL. */
    public static native int nativeDevBuild();

    /** Native Ed25519 verification of a heartbeat response; 1 = valid, 0 = invalid/poison. */
    public static native int nativeVerifyHeartbeat(byte[] responseUtf8, byte[] tokenUtf8);

    /**
     * B3-1 (KI-03): 1 when the loaded native module's own .text SHA-256 baseline (taken in
     * JNI_OnLoad) still matches and no protected prologue shows an INT3/JMP patch; 0 when the
     * section was tampered with or the baseline is unavailable. Same-shape query; never throws.
     */
    public static native int nativeCodeSectionIntact();

    /** B3-1 fail-closed boolean bridge: false when the native library is missing or patched. */
    public static boolean codeSectionIntact() {
        if (!nativeAuthLoaded) return false;
        try {
            return nativeCodeSectionIntact() == 1;
        } catch (Throwable t) {
            return false;
        }
    }

    public static boolean nativeAuthAvailable() {
        return nativeAuthLoaded;
    }

    /**
     * P1-1: the class-body key the attach agent decrypts CHENC1 with.
     *
     * <p>Derived on demand inside native from the ResourceKey that only an authorized handle holds,
     * so nothing in the shipped jar can reproduce it. Returns {@code null} when there is no live
     * handle (no licence, poisoned handle, expired session, missing DLL); callers must fail closed
     * and never substitute a built-in key.</p>
     */
    /**
     * P0-2: decrypts one CHENC1 class body inside the native module.
     *
     * <p>The 32-byte class key is derived from the authorized handle in native and <b>never</b>
     * returned to Java. Replacing the old {@code deriveClassKey()} removed the cheapest attack in
     * both red-team reviews: reflect once on a licensed machine, then decrypt all 1156 bodies
     * offline. Now an attacker who wants the plaintext has to dump a running licensed process, and
     * an attacker who wants to decrypt the jar has nothing to reflect.</p>
     *
     * @return plaintext class bytes, or {@code null} when there is no valid handle / bad blob
     */
    public static byte[] decryptClassBody(byte[] blob, String internalName) {
        long handle = nativeSessionHandle;
        if (handle == 0L || !nativeAuthLoaded || blob == null || internalName == null
                || internalName.isEmpty()) {
            return null;
        }
        try {
            byte[] plain = nativeDecryptClass(handle, blob,
                    internalName.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return plain == null || plain.length == 0 ? null : plain;
        } catch (Throwable ignored) {
            return null;
        }
    }

    /** P0-2: native CHENC1 decryption; the key stays inside the DLL. */
    private static native byte[] nativeDecryptClass(long handle, byte[] blob, byte[] internalName);

    /**
     * A2: per-class authorization gate, called from injected {@code <clinit>} prologues.
     *
     * <p>Red team round 3 (2026-10-22) verdict on the previous shape: <b>decorative</b>. It used to
     * be {@code ifne} on an {@code int} token, so any non-zero value passed and a single
     * {@code return 1} patch at the Java wrapper cleared every gated class at once.</p>
     *
     * <p>Two changes remove both halves of that bypass:</p>
     * <ul>
     *   <li><b>No Java branch.</b> The injected prologue is a single {@code invokestatic} of this
     *       native method - there is no {@code ifne}, no token, and nothing in Java that a one-line
     *       patch can turn into "allow". A caller cannot observe a boolean to flip.</li>
     *   <li><b>Native decides and acts.</b> When the gate denies, the DLL terminates the process
     *       itself (exit code 4, the same contract as every other fail-closed path). The verdict
     *       never crosses the JNI boundary as data.</li>
     * </ul>
     *
     * <p>Bypass cost after this change: patch the VMP-virtualized gate function, or remove the
     * {@code invokestatic} from every gated class body (each is CHENC1-encrypted and
     * manifest-covered). Patching one Java method no longer clears anything.</p>
     *
     * <p>Dev DLLs do not terminate: the gate is a no-op there so unit tests and unlicensed dev runs
     * keep working. Only the release artifact enforces.</p>
     *
     * @param id stable per-class id; native derives a different token per id, so a bypass learned at
     *           one class teaches nothing about the next
     */
    public static native void nativeGateCheck(int id);

    /**
     * D: VMProtect's own image CRC (1 valid / 0 modified / -1 no VMP SDK). The .text baseline taken
     * in JNI_OnLoad cannot see a patch that was already on disk, because it hashes the image it was
     * loaded from; the packer's CRC is computed against the signed build, so it can.
     */
    public static int vmpImageCrc() {
        try {
            return nativeVmpImageCrc();
        } catch (Throwable ignored) {
            return -1;
        }
    }

    /** D: native side of {@link #vmpImageCrc()}. */
    private static native int nativeVmpImageCrc();

    /**
     * G: hardware id derived from firmware (SMBIOS type-1 UUID + C: volume serial), hashed.
     *
     * <p>The Java composite it replaces ({@code hostname|os.name|os.arch|user.name}) was pure system
     * properties: {@code -Duser.name=x} plus a hostname change defeated the per-account device
     * limit. Empty string when the native module cannot read either source; the caller then falls
     * back to the old composite so a machine without SMBIOS can still activate.</p>
     */
    public static String hwid() {
        // No nativeAuthLoaded guard on purpose: the activation CLI loads the DLL with System.load
        // and never sets that flag, and it must report the same id the game does. A missing library
        // surfaces as UnsatisfiedLinkError, which the catch turns into "use the fallback".
        try {
            String value = nativeHwid();
            return value != null && value.matches("[0-9a-f]{64}") ? value : "";
        } catch (Throwable ignored) {
            return "";
        }
    }

    /** G: native hardware id (SMBIOS UUID + volume serial). */
    private static native String nativeHwid();

    /**
     * P1-1 (dev only): the raw class key.
     *
     * <p>Release DLLs return an empty array - the key no longer crosses the JNI boundary at all.
     * This exists so {@code ClassKeyAlignmentTest} can assert that native's HKDF matches the
     * build-time derivation byte for byte.</p>
     */
    public static byte[] deriveClassKey() {
        long handle = nativeSessionHandle;
        if (handle == 0L || !nativeAuthLoaded) {
            return null;
        }
        byte[] key = nativeDeriveClassKey(handle);
        if (key == null || key.length != KEY_LENGTH) {
            return null;
        }
        return key;
    }

    private ChimeraRuntime() {
    }

    // ------------------------------------------------------------------ public API

    /**
     * Legacy dev fallback: overrides the global content key. A value matching
     * {@code [0-9a-fA-F]{16,128}} is treated as hex key material, anything else as a passphrase
     * hashed with SHA-256. Release jars are built with a ResourceKey; use {@link #setResourceKey}.
     */
    public static void setContentKey(String key) {
        if (key == null || key.isBlank()) throw new IllegalArgumentException("content key is empty");
        setContentKey(deriveKeyMaterial(key));
    }

    /**
     * Legacy dev fallback: installs the raw 32-byte global content key. With a native
     * SessionHandle the key is never delivered to Java (see {@link #installNativeHandle}).
     */
    public static void setContentKey(byte[] rawKey) {
        installJavaKey(rawKey, false);
    }

    /**
     * KI-28 dev/no-handle path: installs the product 32-byte ResourceKey used by the build
     * pipeline to encrypt strings/chunks/manifest/VM blobs. In authorized mode the ResourceKey is
     * unwrapped and kept only inside the native SessionHandle, so this API is for demo/dev builds
     * or tests without a native library.
     */
    public static void setResourceKey(String key) {
        if (key == null || key.isBlank()) throw new IllegalArgumentException("resource key is empty");
        setResourceKey(deriveKeyMaterial(key));
    }

    /** Raw-byte variant of {@link #setResourceKey(String)}. */
    public static void setResourceKey(byte[] rawKey) {
        installJavaKey(rawKey, true);
    }

    private static void installJavaKey(byte[] rawKey, boolean resourceKey) {
        if (rawKey == null || rawKey.length != KEY_LENGTH) {
            throw new IllegalArgumentException((resourceKey ? "resource key" : "content key")
                    + " must be " + KEY_LENGTH + " bytes");
        }
        byte[] material = rawKey.clone();
        synchronized (ChimeraRuntime.class) {
            long previousHandle = nativeSessionHandle;
            if (resourceKey) {
                resourceKeyMaterial = material;
                contentKeyMaterial = null;
            } else {
                contentKeyMaterial = material;
                resourceKeyMaterial = null;
            }
            nativeSessionHandle = 0L;
            revokeNativeHandleQuietly(previousHandle);
            clearCachedCredentials();
            lastCanaryCheckNanos = 0L;
            lastRefreshAttemptNanos = 0L;
            refreshInProgress = false;
            kek = null;
            clearStringCache();
            integrityChecked = false;
            poisoned = false;
            serverNonce = 0L;
            serverNonceBytes = null;
            sessionKey = null;
            sessionStampReady = false;
        }
    }

    /**
     * B1: installs a native SessionHandle after a successful canary check. The product content
     * key is never returned to Java; item/session keys are derived through nativeCompute.
     */
    public static void installNativeHandle(long handle) {
        synchronized (ChimeraRuntime.class) {
            nativeSessionHandle = handle;
            lastCanaryCheckNanos = System.nanoTime();
            lastRefreshAttemptNanos = 0L;
            contentKeyMaterial = null;
            // KI-28: the ResourceKey lives only inside the native handle in authorized mode.
            resourceKeyMaterial = null;
            kek = null;
            clearStringCache();
            integrityChecked = false;
            poisoned = false;
            sessionKey = null;
            sessionStampReady = false;
        }
    }

    // ------------------------------------------------------------------ handle lifecycle (KI-26)

    /**
     * B7-pre/KI-26: revokes the native SessionHandle and clears the cached activation credentials.
     * Logout/explicit teardown only; business code keeps running with poison values.
     */
    public static void revokeSession() {
        synchronized (ChimeraRuntime.class) {
            long handle = nativeSessionHandle;
            nativeSessionHandle = 0L;
            lastCanaryCheckNanos = 0L;
            revokeNativeHandleQuietly(handle);
            clearCachedCredentials();
            sessionKey = null;
            sessionStampReady = false;
            markPoison();
        }
    }

    /**
     * B7-pre/KI-26 retry path: a handle that expired (TTL), was revoked, or was LRU-evicted by
     * native state is re-activated once with the cached credentials instead of surfacing a
     * business exception. Returns true when a usable session exists afterwards.
     */
    public static boolean ensureSessionHealthy() {
        long handle = nativeSessionHandle;
        if (handle == 0L || !nativeAuthLoaded) return false;
        if (nativeCanaryOk(handle)) {
            lastCanaryCheckNanos = System.nanoTime();
            return true;
        }
        if (refreshInProgress) return false;
        boolean refreshed = refreshNativeSession();
        if (refreshed) lastCanaryCheckNanos = System.nanoTime();
        return refreshed;
    }

    /** True when the loaded native library is the dev/test flavour (QA hooks compiled in). */
    public static boolean isDevNativeBuild() {
        if (!nativeAuthLoaded) return false;
        try {
            return nativeDevBuild() == 1;
        } catch (Throwable t) {
            return false;
        }
    }

    /** True when the native auth library is loaded (the gate's release anchor). */
    public static boolean isNativeLoaded() {
        return nativeAuthLoaded;
    }

    /**
     * P0-1: re-applies the native release anchor once the DLL is loaded. The environment marker can
     * be resolved before the payload is loaded (early class initialisation); a flipped dev flag
     * would otherwise leave diagnostic overrides enabled for the rest of the process.
     */
    public static void refreshBuildPolicy() {
        try {
            if (nativeAuthLoaded && nativeDevBuild() == 0) {
                DebugSwitches.configure(false);
            }
        } catch (Throwable ignored) {
            // the gate/enforcement points re-check the anchor on their own
        }
    }

    /**
     * P0-1: true when this artifact must enforce the release policy (licence gate, no dev bypass,
     * tamper is fatal).
     *
     * <p>The native DLL is the authoritative anchor: the shipped product embeds the <b>release</b>
     * DLL (VMProtect-protected, {@code nativeDevBuild() == 0}), so deleting the release-only
     * resources or flipping the {@code env.dat} dev flag cannot talk the runtime out of release
     * mode. Without a native payload (dev iteration, unit tests, artifacts built without a DLL) the
     * release-only resources decide, which keeps dev semantics for unprotected jars.</p>
     */
    public static boolean enforceReleasePolicy() {
        try {
            if (nativeAuthLoaded) {
                return nativeDevBuild() != 1;
            }
        } catch (Throwable ignored) {
            // fall through to the build-time anchor
        }
        // SECURITY (audit 2026-10-22 #5): an artifact that ships a native payload knows it is a
        // protected artifact from a build-time constant, not from the editable env.dat flags. If
        // it is somehow running without its image, the payload check halts it; until then the
        // strict policy applies, so no diagnostic override can resurrect in the gap.
        if (ChimeraBuildFlags.payloadRequired()) {
            return true;
        }
        // No native payload and no build-time claim: this is a dev/unit-test classpath or a jar
        // built without a DLL, so the env marker decides (a jar without env.dat is not a
        // protected artifact at all).
        try {
            return DebugSwitches.state() == DebugSwitches.RELEASE;
        } catch (Throwable ignored) {
            return true;
        }
    }

    /**
     * P0-1 "bypass means death": integrity failures that would otherwise only decay into decoy
     * values stop a release artifact outright. In a dev artifact they keep the historical
     * degrade-and-continue behaviour so development and diagnostics stay usable.
     */
    private static void markPoisonFatal(String reason) {
        boolean enforced;
        try {
            enforced = enforceReleasePolicy();
        } catch (Throwable ignored) {
            enforced = true;
        }
        markPoison();
        diagDecoy("fatal " + reason + (enforced ? "" : " (dev artifact: decay only)"));
        if (!enforced) return;
        System.err.println("[chimera] integrity failure: " + reason + "; refusing to run");
        fatalExit(4);
    }

    /**
     * Test seam: records a fail-closed exit instead of killing the test JVM.
     *
     * <p>SECURITY (audit 2026-10-22 #3): inert in every artifact that carries a native payload
     * ({@link ChimeraBuildFlags#testSeams()} is compiled out there) and whenever a release DLL is
     * loaded, so a third-party mod declaring {@code dev.chimera.runtime} cannot silence
     * {@code fatalExit}. The sink is only ever installed, never read back.</p>
     */
    private static volatile java.util.function.IntConsumer haltSink;

    static void setHaltSinkForTests(java.util.function.IntConsumer sink) {
        if (!testSeamsAllowed()) {
            return;
        }
        haltSink = sink;
    }

    /**
     * True when the test seams may influence behaviour: the build kept them AND this process is
     * not running the release native image. A mod can neither reach the build flag (private, and
     * hashed into {@code /chimera/runtime.hash}) nor make a release DLL report {@code dev}.
     */
    static boolean testSeamsAllowed() {
        if (!ChimeraBuildFlags.testSeams()) {
            return false;
        }
        try {
            return !nativeAuthLoaded || nativeDevBuild() == 1;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static void fatalExit(int code) {
        java.util.function.IntConsumer sink = haltSink;
        if (sink != null && testSeamsAllowed()) {
            sink.accept(code);
            throw new IllegalStateException("halt(" + code + ")");
        }
        Runtime.getRuntime().halt(code);
    }

    /**
     * P0-1 marker for "a sealed integrity record exists but does not authenticate". Distinguishes
     * real tampering from "the resource is not there yet" (pre-session decrypt, builds without
     * integrity), which keeps the historical degrade path.
     *
     * <p>A message prefix is used on purpose: every runtime class is injected into the protected jar
     * from an explicit list, so adding a nested exception class here would ship a class the loader
     * never sees and break verification of the enclosing class.</p>
     */
    private static final String TAMPER_MARK = "CHIMERA-TAMPER: ";

    /** Tamper-flavoured integrity failure (subclass of IllegalStateException: no new class file). */
    private static IllegalStateException tamper(String message) {
        return new IllegalStateException(TAMPER_MARK + message);
    }

    private static IllegalStateException tamper(String message, Throwable cause) {
        return new IllegalStateException(TAMPER_MARK + message, cause);
    }

    /** True when this failure was classified as tampering by the integrity checks. */
    private static boolean isTamper(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            String message = cause.getMessage();
            if (message != null && message.startsWith(TAMPER_MARK)) return true;
        }
        return false;
    }

    /** True when a failure chain reports tampering rather than "resource not ready yet". */
    private static boolean tamperFailure(Throwable failure) {
        if (integrityFailure(failure)) return true;
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            String message = cause.getMessage();
            if (message == null) continue;
            String lower = message.toLowerCase(java.util.Locale.ROOT);
            if (lower.contains("hash mismatch") || lower.contains("chunk hash")
                    || lower.contains("runtime class tampered") || lower.contains("runtime class missing")
                    || lower.contains("bad runtime hash") || lower.startsWith("b6:")) {
                return true;
            }
        }
        return false;
    }

    /** Diagnostics/tests: current native handle idle TTL in milliseconds. */
    public static long handleTtlMs() {
        if (!nativeAuthLoaded) return 0L;
        try {
            return nativeHandleTtlMs();
        } catch (Throwable t) {
            return 0L;
        }
    }

    /** Tests: sets the handle TTL through the clamped native setter; returns the effective value. */
    public static long setHandleTtlMsForTest(long ttlMs) {
        if (!nativeAuthLoaded) return 0L;
        try {
            return nativeSetHandleTtlMs(ttlMs);
        } catch (Throwable t) {
            return 0L;
        }
    }

    /** Tests: forces the current handle to look expired (native QA hook); false when no handle. */
    public static boolean expireHandleForTest() {
        long handle = nativeSessionHandle;
        if (handle == 0L || !nativeAuthLoaded) return false;
        try {
            return nativeExpireHandleForTest(handle) == 1;
        } catch (Throwable t) {
            return false;
        }
    }

    /** Tests/diagnostics: raw native canary, 1 = usable handle, 0 = invalid, -1 = no session. */
    public static long handleCanaryForTest() {
        long handle = nativeSessionHandle;
        if (handle == 0L || !nativeAuthLoaded) return -1L;
        try {
            byte[] canary = nativeCompute(handle, new byte[]{NATIVE_OP_CANARY});
            return canary == null || canary.length != 8 ? -1L : bytesToLong(canary, 0);
        } catch (Throwable t) {
            return -1L;
        }
    }

    private static boolean nativeCanaryOk(long handle) {
        if (!nativeAuthLoaded || handle == 0L) return false;
        try {
            byte[] canary = nativeCompute(handle, new byte[]{NATIVE_OP_CANARY});
            return canary != null && canary.length == 8 && bytesToLong(canary, 0) == 1L;
        } catch (Throwable t) {
            return false;
        }
    }

    /**
     * Re-activates with the cached credentials after the native handle became unusable. Rate
     * limited so a burst of failing operations cannot hammer the license server.
     */
    private static boolean refreshNativeSession() {
        String account = authCachedAccount;
        String password = authCachedPassword;
        String hwid = authCachedHwid;
        if (account == null || password == null || hwid == null) return false;
        long now = System.nanoTime();
        if (lastRefreshAttemptNanos != 0L && now - lastRefreshAttemptNanos >= 0
                && now - lastRefreshAttemptNanos < AUTH_REFRESH_BACKOFF_NANOS) {
            return false;
        }
        synchronized (ChimeraRuntime.class) {
            if (poisoned) return false;
            lastRefreshAttemptNanos = now;
            refreshInProgress = true;
            try {
                nativeSessionHandle = 0L;
                lastCanaryCheckNanos = 0L;
                return authenticate(account, password, hwid);
            } finally {
                refreshInProgress = false;
            }
        }
    }

    /**
     * Runs one nativeCompute op against the live handle, re-authenticating once when the handle
     * expired. Canary probing is throttled to once per second so per-frame VM calls stay cheap.
     */
    private static byte[] nativeComputeOnSession(byte op, byte[] payload) {
        long handle = nativeSessionHandle;
        if (handle == 0L || !nativeAuthLoaded) return null;
        long now = System.nanoTime();
        long lastCheck = lastCanaryCheckNanos;
        boolean fresh = lastCheck != 0L && now - lastCheck >= 0
                && now - lastCheck < CANARY_CHECK_INTERVAL_NANOS;
        if (!fresh && !ensureSessionHealthy()) return null;
        long active = nativeSessionHandle;
        if (active == 0L) return null;
        try {
            return nativeComputeOp(active, op, payload);
        } catch (Throwable t) {
            if (nativeCanaryOk(active)) throw t;
            if (!refreshNativeSession()) throw t;
            long refreshed = nativeSessionHandle;
            if (refreshed == 0L) throw t;
            lastCanaryCheckNanos = System.nanoTime();
            return nativeComputeOp(refreshed, op, payload);
        }
    }

    private static void revokeNativeHandleQuietly(long handle) {
        if (handle == 0L || !nativeAuthLoaded) return;
        try {
            nativeRevokeHandle(handle);
        } catch (Throwable ignored) {
            // best-effort wipe; the slot's TTL still applies
        }
    }

    private static void clearCachedCredentials() {
        authCachedAccount = null;
        authCachedPassword = null;
        authCachedHwid = null;
    }

    /**
     * Decrypts and caches one string from {@code /chimera/strings.dat}.
     * <p>Never throws on a missing/invalid key: it poisons the runtime state and returns a
     * deterministic decoy string so that user code keeps running with wrong data instead of
     * hitting a catchable authorization exception.</p>
     */
    private static void diagDecrypt(String line) {
        try {
            java.nio.file.Path dir = java.nio.file.Path.of(
                    System.getProperty("user.home", "."), ".chimera");
            java.nio.file.Files.createDirectories(dir);
            java.nio.file.Files.writeString(dir.resolve("decrypt-diag.log"),
                    line + System.lineSeparator(), java.nio.charset.StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE,
                    java.nio.file.StandardOpenOption.APPEND);
        } catch (Throwable ignored) {
        }
    }

    private static void diagDecoy(String line) {
        try {
            java.nio.file.Path dir = java.nio.file.Path.of(
                    System.getProperty("user.home", "."), ".chimera");
            java.nio.file.Files.createDirectories(dir);
            java.nio.file.Files.writeString(dir.resolve("decoy-diag.log"),
                    line + System.lineSeparator(), java.nio.charset.StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE,
                    java.nio.file.StandardOpenOption.APPEND);
        } catch (Throwable ignored) {
        }
    }

    public static String decryptStr(int id) {
        verifyRuntimeHash();
        selfCheck();
        if (!poisoned && nativeSessionHandle == 0L) {
            // Pre-gate class initialisation may decrypt strings; renew the persisted session once
            // instead of caching a fail-closed decoy. Tamper/poison states never reach this path.
            try {
                ChimeraSessionRestorer.restoreOnce();
            } catch (Throwable ignored) {
                // stays fail-closed
            }
        }
        if (poisoned) {
            diagDecoy("poisoned id=" + id + " handle=" + nativeSessionHandle);
            if (Boolean.getBoolean("chimera.native.debug")) {
                System.err.println("[chimera-native] decryptStr(" + id + ") before load: poisoned");
            }
            return decoy(id);
        }
        try {
            String value = cachedString(id);
            if (value == null) value = decryptString(id);
            return value;
        } catch (Throwable t) {
            if (Boolean.getBoolean("chimera.native.debug")) {
                System.err.println("[chimera-native] decryptStr(" + id + ") failed");
                t.printStackTrace();
            }
            // pre-gate decoy: before a session exists this is "not ready yet", not tamper.
            // Retry once after restoring the persisted session; only a real failure with a live
            // handle poisons the runtime (fail closed).
            if (nativeSessionHandle == 0L) {
                // A string-table MAC/format failure is tamper, not "not ready yet": poison even
                // before a session exists, otherwise a patched strings.dat would silently run as
                // decoy-only with isKeyHealthy() still true (fail-closed would never fire).
                if (integrityFailure(t)) {
                    diagDecoy("integrity id=" + id + " " + t);
                    markPoisonFatal("string table id=" + id + ": " + t.getMessage());
                    return decoy(id);
                }
                try {
                    if (ChimeraSessionRestorer.restoreOnce()) {
                        return decryptString(id);
                    }
                } catch (Throwable ignored) {
                    // fall through to the decoy
                }
                diagDecoy("pre-gate id=" + id);
                return decoy(id);
            }
            diagDecoy("exception id=" + id + " " + t);
            if (tamperFailure(t)) {
                markPoisonFatal("string table id=" + id + ": " + t.getMessage());
            } else {
                markPoison();
            }
            return decoy(id);
        }
    }

    /**
     * Bootstrap method for fragmented methods. Verifies the integrity manifest, decrypts the
     * chunk, defines it as a hidden nestmate of the caller and returns a constant call site for
     * its {@code run} method.
     */
    public static CallSite bootstrapChunk(MethodHandles.Lookup caller, String name, MethodType type,
                                          int id, String resource, String owner) {
        verifyRuntimeHash();
        if (poisoned) return poisonSite(type, name);
        long started = timingNow();
        byte[] classBytes = null;
        try {
            selfCheck();
            ensureEnv();

            byte[] data = readResource(normalizeResourcePath(resource));
            if (data == null) throw new IllegalStateException("chunk resource missing: " + resource);

            DataInputStream in = new DataInputStream(new ByteArrayInputStream(data));
            if (in.readInt() != CHUNK_MAGIC) throw new IllegalStateException("bad chunk magic: " + resource);
            int chunkId = in.readInt();
            if (chunkId != id) throw new IllegalStateException("chunk id mismatch: " + chunkId + " != " + id);
            byte[] nonce = readNonce(in);
            byte[] ciphertext = readBlock(in, 0);

            classBytes = decryptResource("chunk", id, nonce, ciphertext,
                    ("chunk/" + id).getBytes(StandardCharsets.UTF_8));
            // B6: authenticated build-time hash must match before the bytes reach the JVM, so a
            // Frida hook that replaces defineHiddenClass arguments is detected here.
            try {
                verifyChunkIntegrity(id, classBytes);
            } catch (IllegalStateException e) {
                if (isTamper(e)) throw e;
                throw tamper("chunk integrity " + id + ": " + e.getMessage(), e);
            }

            MethodHandles.Lookup hidden = caller.defineHiddenClass(classBytes, true,
                    MethodHandles.Lookup.ClassOption.NESTMATE);
            Class<?> hiddenClass = hidden.lookupClass();
            // B6: primary verification is AFTER defineHiddenClass on the bytes the VM actually
            // installed (JVMTI GetBytecodes in native). Structural checks always run; byte-level
            // match is PARTIAL when the native JVMTI path is unavailable (-1).
            try {
                verifyDefinedChunk(id, caller.lookupClass(), hiddenClass, type);
                verifyDefinedChunkBytes(hiddenClass, classBytes);
            } catch (IllegalStateException e) {
                throw tamper("chunk post-define " + id + ": " + e.getMessage(), e);
            }
            MethodHandle handle = caller.findStatic(hiddenClass, "run", type);
            return new ConstantCallSite(handle);
        } catch (Throwable t) {
            // Deliberately no exception: degraded execution returns type-correct poison values.
            if (Boolean.getBoolean("chimera.native.debug")) {
                System.err.println("[chimera-native] bootstrap failed for chunk " + id + ": " + t);
                t.printStackTrace();
            }
            if (isTamper(t)) {
                markPoisonFatal("chunk " + id + ": " + t.getMessage());
            } else {
                markPoison();
            }
            return poisonSite(type, name);
        } finally {
            if (classBytes != null) {
                wipe(classBytes);
                wipeCount++;
            }
            long elapsed = timingNow() - started;
            lastBootstrapNanos = elapsed;
            if (classBytes != null) {
                lastWipeZeroed = isAllZero(classBytes);
            }
            recordTimingSample(elapsed);
        }
    }

    /**
     * Verifies {@code /chimera/manifest.dat} against its HMAC and every listed class against its
     * SHA-256. Successful verification is cached; failures are re-thrown on every call.
     * {@code -Dchimera.verify=false} skips the check (debug builds only).
     */
    public static void selfCheck() {
        verifyRuntimeHash();
        // #9: the full chimera/** resource manifest is authoritative and cached; calling it here
        // keeps the guarantee even for entry points that never pass through the gate.
        verifyResourceManifest();
        if (integrityChecked) return;
        synchronized (ChimeraRuntime.class) {
            if (integrityChecked) return;
            if ("false".equalsIgnoreCase(System.getProperty(VERIFY_PROPERTY))) {
                integrityChecked = true;
                return;
            }
            try {
                byte[] manifest = readResource("/chimera/manifest.dat");
                if (manifest == null) {
                    // Integrity checking is optional (--no-integrity builds have no manifest).
                    if (readResource("/chimera/manifest.mac") == null) {
                        integrityChecked = true;
                        return;
                    }
                    throw new IllegalStateException("integrity manifest missing");
                }
                byte[] sealed = readResource("/chimera/manifest.mac");
                if (sealed == null) throw tamper("integrity mac missing");
                if (sealed.length != MANIFEST_SEALED_MAC_LENGTH) {
                    throw tamper("integrity mac has unsupported length: " + sealed.length);
                }
                ensureEnv();
                byte[] macNonce = new byte[MANIFEST_NONCE_LENGTH];
                System.arraycopy(sealed, 0, macNonce, 0, macNonce.length);
                byte[] macCiphertext = new byte[sealed.length - macNonce.length];
                System.arraycopy(sealed, macNonce.length, macCiphertext, 0, macCiphertext.length);
                // KI-28: the sealed digest is opened by native op9 (ResourceKey only inside the
                // handle) or by the Java no-handle fallback; the key never crosses into Java.
                byte[] expectedDigest = decryptResource(MANIFEST_KIND, MANIFEST_ID, macNonce,
                        macCiphertext, MANIFEST_AAD.getBytes(StandardCharsets.UTF_8));
                if (!constantTimeEquals(expectedDigest, sha256(manifest))) {
                    if (Boolean.getBoolean("chimera.native.debug")) {
                        System.err.println("[chimera-native] manifest mac mismatch handle="
                                + nativeSessionHandle);
                    }
                    throw tamper("integrity check failed: manifest.mac");
                }
                try {
                    verifyManifest(manifest);
                } catch (IllegalStateException e) {
                    if (isTamper(e)) throw e;
                    throw tamper("manifest entry: " + e.getMessage(), e);
                } catch (Throwable t) {
                    throw tamper("manifest entry: " + t.getMessage(), t);
                }
                integrityChecked = true;
            } catch (Throwable t) {
                if (Boolean.getBoolean("chimera.native.debug")) {
                    System.err.println("[chimera-native] selfCheck failed");
                    t.printStackTrace();
                }
                integrityChecked = true;
                // P0-1: a sealed-manifest mismatch is tampering, not "not ready yet" (a build
                // without integrity has no manifest at all and returns above). Missing resources and
                // pre-session decryption failures keep the M2 degrade path.
                if (isTamper(t)) {
                    markPoisonFatal("manifest: " + t.getMessage());
                } else {
                    // M2: degrade through poisoned state, never surface an authorization exception.
                    markPoison();
                }
            }
        }
    }

    // ------------------------------------------------------------------ #9 resource manifest

    /**
     * #9 (audit 2026-10-22): full-coverage integrity check for {@code chimera/**}.
     *
     * <p>Before this existed, {@code manifest.dat} only listed classes and {@code runtime.hash}
     * only the injected runtime classes, so <b>no</b> resource was covered: {@code auth.dat},
     * {@code env.dat}, {@code attach/agent.jar} (and its {@code protected.txt}),
     * {@code res/native.dat}, {@code strings.dat} and {@code wm/*} could be rewritten at will and
     * nothing noticed. Deleting one {@code pubkey=} line was enough to fail the gate open.</p>
     *
     * <p>Two phases, because the key that authenticates the manifest lives in the native image that
     * the manifest itself protects:</p>
     * <ol>
     *   <li>Before the DLL exists, the payload loaders hash the native image itself against the
     *       manifest ({@link ChimeraStealthLoader#verifyPayloadManifest}, same fail-closed rule as
     *       the CHS1 CRC) - a manifest that cannot yet be authenticated can still prove that the
     *       image it protects is the one that was built.</li>
     *   <li>{@link #verifyResourceManifest()} runs immediately after the native image is loaded and
     *       before {@code loadAuthConfig()} / the gate. The manifest is now authenticated by
     *       {@code nativeVerifyManifest} (HMAC key = compile-time constant of the DLL), so a
     *       missing, extra or rewritten {@code chimera/**} entry halts the process with exit
     *       code 4 in a release artifact.</li>
     * </ol>
     *
     * <p>Results are cached: the whole check (including a 13 MB {@code native.dat}) runs once.</p>
     */
    private static final int MANIFEST_HMAC_BYTES = 32;
    private static final String MANIFEST_RESOURCE = "/chimera/manifest.dat";
    private static final String MANIFEST_MAC_RESOURCE = "/chimera/manifest.mac";
    private static final String MANIFEST_HMAC_RESOURCE = "/chimera/manifest.hmac";
    private static final String MANIFEST_PREFIX = "chimera/";
    private static final String MANIFEST_HEADER_FULL = "CHM2";
    /** Records that cannot list themselves; the runtime exempts exactly these from "unlisted". */
    private static final String[] MANIFEST_RESERVED = {
            "chimera/manifest.dat", "chimera/manifest.mac", "chimera/manifest.hmac"};
    /** Resources whose presence means this artifact must have a native image loaded. */
    private static final String[] NATIVE_PAYLOAD_ENTRIES = {
            "chimera/res/native.dat", "chimera/embedded.dll"};

    private static volatile boolean resourceManifestChecked;

    /**
     * Authoritative resource check. Call after the native image is loaded and before any
     * {@code chimera/**} resource is consumed ({@code loadAuthConfig}, the string table, the agent
     * jar, the payload). Cached; safe to call from every entry point.
     */
    public static void verifyResourceManifest() {
        if (resourceManifestChecked) return;
        synchronized (ChimeraRuntime.class) {
            if (resourceManifestChecked) return;
            resourceManifestChecked = true;
            try {
                checkResourceManifest();
            } catch (Throwable t) {
                if (Boolean.getBoolean("chimera.native.debug")) {
                    System.err.println("[chimera-native] verifyResourceManifest failed");
                    t.printStackTrace();
                }
                diagDecoy("manifest: " + t.getMessage());
                if (enforceReleasePolicy()) {
                    markPoisonFatal("resource manifest: " + t.getMessage());
                } else {
                    System.err.println("[chimera] resource manifest check failed on a dev artifact"
                            + " (not enforced): " + t.getMessage());
                }
            }
        }
    }

    private static void checkResourceManifest() throws Exception {
        byte[] manifest = readResource(MANIFEST_RESOURCE);
        if (manifest == null) {
            // SECURITY (red team, 2026-10-22): this used to return silently whenever manifest.dat
            // AND manifest.mac were both absent ("unprotected dev artifact"). That made every
            // manifest-protected control - the runtime classes, and therefore decryptClassBody and
            // classGate - bypassable by DELETING two entries: no key, no patch to the DLL, ~30
            // minutes. A release artifact always ships a manifest, so its absence is tampering.
            if (enforceReleasePolicy()) {
                throw tamper("integrity manifest missing on a release artifact");
            }
            System.err.println("[chimera] resource manifest: absent on a dev artifact,"
                    + " chimera/** integrity check skipped");
            return;
        }
        String header = manifestHeader(manifest);
        Map<String, String> expected = parseManifest(manifest);
        // 1. Authenticity. Without the build-pinned key there is no way to tell an edited
        //    resource from an edited manifest, so say so instead of implying coverage.
        boolean pinned = nativeAuthLoaded && manifestKeyPinned();
        if (pinned) {
            byte[] tag = readResource(MANIFEST_HMAC_RESOURCE);
            if (tag == null) throw tamper("manifest hmac missing");
            if (tag.length != MANIFEST_HMAC_BYTES) {
                throw tamper("manifest hmac has unsupported length: " + tag.length);
            }
            if (!verifyManifestHmac(manifest, tag)) {
                throw tamper("manifest hmac mismatch");
            }
        } else {
            System.err.println("[chimera] resource manifest: NOT authenticated (native library"
                    + " carries no pinned manifest key); hashes only detect corruption");
            diagDecoy("manifest: no pinned key, hmac not enforced");
        }
        // 2. A manifest that ships a native payload proves the build had one. Its absence means
        //    the payload was deleted to dodge the anchor (or the build is broken): fail closed
        //    regardless of what env.dat now claims.
        if (!nativeAuthLoaded && listsNativePayload(expected)) {
            throw tamper("native payload missing (manifest lists one)");
        }
        // 3. Every listed entry must exist with the recorded digest.
        verifyManifestEntries(expected);
        // 4. CHM2 only: nothing may be smuggled in under chimera/.
        if (MANIFEST_HEADER_FULL.equals(header)) {
            verifyNoUnlistedResources(expected);
        }
    }

    /**
     * Safe wrapper: a DLL built before #9 does not export the manifest surface. That is "no pinned
     * key" (the old, unenforced behaviour), never a hard failure - the jar must not brick on an
     * older native image.
     */
    private static boolean manifestKeyPinned() {
        try {
            return nativeManifestKeyPinned();
        } catch (Throwable unavailable) {
            diagDecoy("manifest: native manifest key surface unavailable");
            return false;
        }
    }

    private static boolean verifyManifestHmac(byte[] manifest, byte[] tag) {
        try {
            return nativeVerifyManifest(manifest, tag);
        } catch (Throwable unavailable) {
            diagDecoy("manifest: native verify unavailable");
            return false;
        }
    }

    private static boolean listsNativePayload(Map<String, String> expected) {        for (String name : NATIVE_PAYLOAD_ENTRIES) {
            if (expected.containsKey(name)) return true;
        }
        return false;
    }

    /**
     * Enumerates the {@code chimera/} entries of the artifact. Returns {@code null} when the jar is
     * not reachable as a file (nested/Fabric-remapped loaders): the caller then logs that the
     * "unlisted resource" rule could not run rather than passing silently.
     */
    private static java.util.Set<String> artifactResourceNames() {
        java.nio.file.Path artifact = artifactPath();
        if (artifact == null) return null;
        try {
            if (!java.nio.file.Files.isRegularFile(artifact)) return null;
            java.util.Set<String> names = new java.util.TreeSet<>();
            try (java.util.zip.ZipFile zip = new java.util.zip.ZipFile(artifact.toFile())) {
                java.util.Enumeration<? extends java.util.zip.ZipEntry> entries = zip.entries();
                while (entries.hasMoreElements()) {
                    java.util.zip.ZipEntry entry = entries.nextElement();
                    if (entry.isDirectory()) continue;
                    String name = entry.getName();
                    if (name.startsWith(MANIFEST_PREFIX)) names.add(name);
                }
            }
            return names;
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static void verifyNoUnlistedResources(Map<String, String> expected) {
        java.util.Set<String> actual = artifactResourceNames();
        if (actual == null) {
            System.err.println("[chimera] resource manifest: artifact not enumerable,"
                    + " unlisted-resource check skipped");
            diagDecoy("manifest: not enumerable, extra-entry check skipped");
            return;
        }
        for (String name : actual) {
            boolean reserved = false;
            for (String exempt : MANIFEST_RESERVED) {
                if (exempt.equals(name)) {
                    reserved = true;
                    break;
                }
            }
            // Per-chunk payloads (chimera/chunks/*, chimera/classes/*) are AES-GCM sealed with a
            // bound AAD and a sealed digest record, so they are covered without being listed.
            if (reserved || name.startsWith("chimera/chunks/")
                    || name.startsWith("chimera/classes/")) {
                continue;
            }
            if (expected.containsKey(name)) continue;
            throw new IllegalStateException("unlisted resource: " + name);
        }
    }

    private static String manifestHeader(byte[] manifest) {
        String text = new String(manifest, StandardCharsets.UTF_8);
        int newline = text.indexOf('\n');
        return trimCarriageReturn(newline < 0 ? text : text.substring(0, newline));
    }

    /** Parses a {@code CHM1}/{@code CHM2} manifest into path → sha256-hex. */
    private static Map<String, String> parseManifest(byte[] manifest) {
        String text = new String(manifest, StandardCharsets.UTF_8);
        String[] lines = text.split("\n", -1);
        String header = lines.length == 0 ? "" : trimCarriageReturn(lines[0]);
        if (!"CHM1".equals(header) && !MANIFEST_HEADER_FULL.equals(header)) {
            throw new IllegalStateException("integrity check failed: manifest header");
        }
        Map<String, String> entries = new java.util.LinkedHashMap<>();
        for (int i = 1; i < lines.length; i++) {
            String line = trimCarriageReturn(lines[i]);
            if (line.isEmpty()) continue;
            int separator = line.indexOf("  ");
            if (separator <= 0 || separator + 2 >= line.length()) {
                throw new IllegalStateException("integrity check failed: malformed manifest entry");
            }
            entries.put(line.substring(separator + 2), line.substring(0, separator));
        }
        return entries;
    }

    /** Streams each listed entry through SHA-256; never materialises large blobs (native.dat). */
    private static void verifyManifestEntries(Map<String, String> expected) {
        ClassLoader loader = ChimeraRuntime.class.getClassLoader();
        if (loader == null) loader = ClassLoader.getSystemClassLoader();
        for (Map.Entry<String, String> entry : expected.entrySet()) {
            String path = entry.getKey();
            String actual = resourceSha256Hex(loader, path);
            if (actual == null) throw new IllegalStateException("integrity check failed: " + path);
            if (!constantTimeEquals(entry.getValue().getBytes(StandardCharsets.US_ASCII),
                    actual.getBytes(StandardCharsets.US_ASCII))) {
                throw new IllegalStateException("integrity check failed: " + path);
            }
        }
    }

    /** SHA-256 hex of a classpath resource, or null when it is absent. Streams, never buffers. */
    private static String resourceSha256Hex(ClassLoader loader, String path) {
        String name = path.startsWith("/") ? path.substring(1) : path;
        try (InputStream in = loader.getResourceAsStream(name)) {
            if (in == null) return null;
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] chunk = new byte[64 * 1024];
            int read;
            while ((read = in.read(chunk)) > 0) digest.update(chunk, 0, read);
            return hex(digest.digest());
        } catch (IOException e) {
            throw new IllegalStateException("resource read failed: " + path, e);
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException("sha-256 failed", e);
        }
    }

    /** Artifact file for the running classes; null when the loader does not expose one. */
    private static java.nio.file.Path artifactPath() {
        try {
            java.security.CodeSource source =
                    ChimeraRuntime.class.getProtectionDomain().getCodeSource();
            java.net.URL location = source == null ? null : source.getLocation();
            if (location != null && "file".equals(location.getProtocol())) {
                return java.nio.file.Path.of(location.toURI());
            }
        } catch (Throwable ignored) {
            // Fabric loaders may hide the code source; fall back to a resource URL below.
        }
        try {
            java.net.URL marker = ChimeraRuntime.class.getResource(MANIFEST_RESOURCE);
            if (marker == null) marker = ChimeraRuntime.class.getResource("/chimera/env.dat");
            if (marker == null) return null;
            String text = marker.toString();
            int bang = text.indexOf("!/");
            if (text.startsWith("jar:") && bang > 4) {
                String file = text.substring(4, bang);
                if (file.startsWith("file:")) {
                    return java.nio.file.Path.of(java.net.URI.create(file));
                }
            }
        } catch (Throwable ignored) {
            // Not a jar-backed artifact.
        }
        return null;
    }

    // ------------------------------------------------------------------ M2 entanglement / session

    /**
     * Rotates the server-issued nonce. The session key is re-derived from the content key and
     * the new nonce, and the cached session stamp is invalidated so any hardcoded old stamp is
     * detected by {@link #verifySessionStamp(long)}.
     */
    public static void updateServerNonce(long nonce) {
        byte[] bytes = new byte[AUTH_NONCE_LENGTH];
        System.arraycopy(longBytes(nonce), 0, bytes, 0, 8);
        System.arraycopy(longBytes(nonce ^ POISON_KEY), 0, bytes, 8, 8);
        applyServerNonce(bytes, nonce);
    }

    /**
     * Installs the 16-byte server nonce obtained from activation/heartbeat. The session key and
     * every session stamp are re-derived from the new nonce, so hardcoded old stamps/secrets fail.
     */
    public static void updateServerNonce(byte[] nonce) {
        if (nonce == null || nonce.length != AUTH_NONCE_LENGTH) {
            markPoison();
            return;
        }
        long folded = bytesToLong(nonce, 0) ^ bytesToLong(nonce, 8);
        applyServerNonce(nonce.clone(), folded);
    }

    private static void applyServerNonce(byte[] nonceBytes, long folded) {
        synchronized (ChimeraRuntime.class) {
            serverNonceBytes = nonceBytes;
            serverNonce = folded;
            sessionKey = null;
            sessionStampReady = false;
            sessionEpoch++;
            try {
                if ((nativeSessionHandle != 0L || kek() != null) && sessionKey() != null) {
                    poisoned = false;
                } else {
                    markPoison();
                }
            } catch (Throwable t) {
                markPoison();
            }
        }
    }

    /** Current 16-byte nonce; a long-only nonce is expanded deterministically. */
    private static byte[] currentNonceBytes() {
        byte[] bytes = serverNonceBytes;
        if (bytes != null) {
            return bytes;
        }
        byte[] fallback = new byte[AUTH_NONCE_LENGTH];
        long value = serverNonce;
        System.arraycopy(longBytes(value), 0, fallback, 0, 8);
        System.arraycopy(longBytes(value ^ POISON_KEY), 0, fallback, 8, 8);
        return fallback;
    }

    public static long sessionEpoch() {
        return sessionEpoch;
    }

    /**
     * Stable stamp for the current (session key, nonce). The transformer stores it on method
     * entry and verifies it before returning: a hardcoded stamp from an older nonce fails and
     * poisons the runtime silently.
     */
    public static long sessionStamp() {
        if (sessionStampReady) return cachedSessionStamp;
        synchronized (ChimeraRuntime.class) {
            if (sessionStampReady) return cachedSessionStamp;
            try {
                ensureEnv();
                byte[] key = sessionKey();
                if (key == null) throw new IllegalStateException("no session key");
                byte[] digest = sha256(concat(key, currentNonceBytes(),
                        "chimera/session-stamp/v1".getBytes(StandardCharsets.UTF_8)));
                cachedSessionStamp = bytesToLong(digest, 0);
                sessionStampReady = true;
                return cachedSessionStamp;
            } catch (Throwable t) {
                markPoison();
                return POISON_KEY ^ serverNonce ^ (System.nanoTime() & 0xFFL);
            }
        }
    }

    /** Called at every return of an entangled method; stale stamp == nonce rotated == poison. */
    public static void verifySessionStamp(long stamp) {
        if (poisoned) return;
        if (stamp != sessionStamp()) markPoison();
    }

    /**
     * Neutral mask: 0 on a healthy session (semantics preserved exactly), otherwise a
     * nonce/time-derived poison value. The poison term is
     * {@code sessionKey ^ serverNonce ^ (nanoTime & 0xFF)}, so it changes after every nonce
     * rotation instead of being a constant an attacker can hardcode.
     */
    public static long entanglementMask() {
        if (poisoned) return poisonMask();
        try {
            ensureEnv();
            if (nativeSessionHandle == 0L && kek() == null) {
                throw new IllegalStateException("no key");
            }
            if (sessionKey() == null) throw new IllegalStateException("no session key");
            return 0L;
        } catch (Throwable t) {
            markPoison();
            return poisonMask();
        }
    }

    public static int intMask() {
        long mask = entanglementMask();
        if (mask == 0L) {
            return 0;
        }
        // For a poisoned session XOR with the sign bit: the returned business int is always
        // negative (e.g. 47 -> 0x8000002F), matching the NaN semantics of doubleMask.
        return Integer.MIN_VALUE;
    }

    // ------------------------------------------------------------------ M7/A3: unified poison shapes

    /**
     * M7/A3: failure shape for an injected pre-game check (non-void method). Must match the M2
     * poison form, not 0/0L/0.0/null, so an attacker cannot recognize the PGC failure by its
     * return value distribution. The session is poisoned before returning.
     */
    public static int pregamePoisonInt() {
        markPoison();
        return Integer.MIN_VALUE;
    }

    /** M7/A3: M2 long poison shape (sign bit flipped). */
    public static long pregamePoisonLong() {
        markPoison();
        return Long.MIN_VALUE;
    }

    /** M7/A3: M2 float poison shape. */
    public static float pregamePoisonFloat() {
        markPoison();
        return Float.NaN;
    }

    /** M7/A3: M2 double poison shape. */
    public static double pregamePoisonDouble() {
        markPoison();
        return Double.NaN;
    }

    // ------------------------------------------------------------------ M9/A4: non-sentinel VM poison

    /**
     * M9/A4: VM failure value for int returns. A fixed -1 is enumerable by an attacker, so this is
     * derived from the poisoned session key and changes per call (interim until the B1
     * SessionHandle/nativeCompute mode lands). It is deliberately not a constant sentinel.
     */
    public static int vmPoisonInt() {
        long key = dynamicKey();
        return (int) (key ^ (key >>> 32));
    }

    /** M9/A4: VM failure value for long returns (session-derived, not -1L). */
    public static long vmPoisonLong() {
        return dynamicKey();
    }

    /**
     * M9/A4: VM failure value for double returns. A finite pseudo-random value in [1,2), so NaN
     * is not a fixed "poison" signature. Interim until the B1 handle-poison mode.
     */
    public static double vmPoisonDouble() {
        long key = dynamicKey();
        long bits = (key & 0x000FFFFFFFFFFFFFL) | 0x3FF0000000000000L;
        return Double.longBitsToDouble(bits);
    }

    /**
     * Final return-site mask for int results. Per-operation masks may cancel when an even number
     * of int operations was entangled, so the return site applies a guaranteed sign flip whenever
     * the session is poisoned (healthy sessions return the value untouched).
     */
    public static int maskIntResult(int value) {
        return entanglementMask() == 0L ? value : (value ^ Integer.MIN_VALUE);
    }

    /** Final return-site mask for long results (guaranteed sign bit when poisoned). */
    public static long maskLongResult(long value) {
        return entanglementMask() == 0L ? value : (value ^ Long.MIN_VALUE);
    }

    public static long longMask() {
        return entanglementMask();
    }

    public static double doubleMask() {
        return entanglementMask() == 0L ? 1.0d : Double.NaN;
    }

    public static float floatMask() {
        return entanglementMask() == 0L ? 1.0f : Float.NaN;
    }

    /**
     * Dynamic key bound to (sessionKey, nonce, nanoTime). Valid session -> usable key;
     * invalid session -> non-zero poison key, never an exception.
     */
    public static long dynamicKey() {
        if (poisoned) return poisonKey();
        try {
            ensureEnv();
            if (nativeSessionHandle != 0L) {
                byte[] derived = nativeComputeOnSession(NATIVE_OP_DYNAMIC_KEY,
                        currentNonceBytes());
                if (derived == null || derived.length < 8) {
                    throw new IllegalStateException("native dynamic key failed");
                }
                return bytesToLong(derived, 0) ^ (System.nanoTime() & 0xFFL);
            }
            byte[] key = sessionKey();
            if (key == null) throw new IllegalStateException("no session key");
            byte[] digest = sha256(concat(key, currentNonceBytes(),
                    "chimera/dynamic-key/v1".getBytes(StandardCharsets.UTF_8)));
            return bytesToLong(digest, 0) ^ (System.nanoTime() & 0xFFL);
        } catch (Throwable t) {
            markPoison();
            return poisonKey();
        }
    }

    private static volatile boolean runtimeHashChecked;

    /**
     * M3/M8 integrity: verify the injected runtime classes against /chimera/runtime.hash before
     * any core operation. A patched runtime class poisons the session silently.
     */
    public static void verifyRuntimeHash() {
        // Phase 0 (C-01): release builds ignore the skip flag; the hash check always runs.
        if (DebugSwitches.propertyTrue("chimera.runtime.hash.skip")) {
            runtimeHashChecked = true;
            return;
        }
        if (runtimeHashChecked) return;
        synchronized (ChimeraRuntime.class) {
            if (runtimeHashChecked) return;
            try {
                byte[] data = readResource("/chimera/runtime.hash");
                if (data == null) {
                    // #5: a payload-carrying artifact always ships its runtime hashes, so a missing
                    // record there is tampering (the catch below halts it). A classpath without the
                    // resource is not a Chimera artifact at all (unit tests, dev engine runs) and
                    // must not poison the session.
                    if (!ChimeraBuildFlags.payloadRequired()) {
                        return;
                    }
                    throw new IllegalStateException("runtime hash missing");
                }
                String[] lines = new String(data, StandardCharsets.UTF_8).split("\n", -1);
                if (lines.length < 2 || !"CHR1".equals(trimCarriageReturn(lines[0]))) {
                    throw new IllegalStateException("bad runtime hash header");
                }
                ClassLoader loader = ChimeraRuntime.class.getClassLoader();
                if (loader == null) loader = ClassLoader.getSystemClassLoader();
                for (int i = 1; i < lines.length; i++) {
                    String line = trimCarriageReturn(lines[i]);
                    if (line.isEmpty()) continue;
                    int separator = line.indexOf("  ");
                    if (separator <= 0) throw new IllegalStateException("bad runtime hash entry");
                    String expected = line.substring(0, separator);
                    String path = line.substring(separator + 2);
                    byte[] classBytes = readClasspathResource(loader, "/" + path);
                    if (classBytes == null) throw new IllegalStateException("runtime class missing: " + path);
                    if (!constantTimeEquals(expected.getBytes(StandardCharsets.US_ASCII),
                            hex(sha256(classBytes)).getBytes(StandardCharsets.US_ASCII))) {
                        throw new IllegalStateException("runtime class tampered: " + path);
                    }
                }
            } catch (Throwable t) {
                if (Boolean.getBoolean("chimera.native.debug")) {
                    System.err.println("[chimera-native] verifyRuntimeHash failed");
                    t.printStackTrace();
                }
                // P0-1: a runtime class that does not match the shipped hash is tampering, not a
                // transient state: a release artifact stops here instead of decaying into decoys.
                markPoisonFatal("runtime hash: " + t.getMessage());
            } finally {
                runtimeHashChecked = true;
            }
        }
    }

    static void verifyRuntimeHashBridge() {
        verifyRuntimeHash();
    }

    /**
     * B6 / KI-28: compares decrypted hidden-class fragment bytes against the build-time hash stored
     * in {@code /chimera/chunks/chunk_<id>.hash}. The whole record is AES-GCM sealed with
     * {@code HKDF(kek, envSalt, "chimera/v1/chunk-hash/<id>")}: the runtime opens it through native
     * op9 DECRYPT_DATA (ResourceKey never enters Java) or the Java no-handle fallback, then compares
     * the digest. Failure flows through bootstrapChunk's catch: poison, no throw.
     */
    private static void verifyChunkIntegrity(int id, byte[] classBytes) {
        try {
            byte[] data = readResource("/chimera/chunks/chunk_" + id + ".hash");
            if (data == null) throw new IllegalStateException("chunk hash missing: " + id);
            if (data.length != CHUNK_HASH_SEALED_LENGTH) {
                throw new IllegalStateException("chunk hash record has unsupported length: " + data.length);
            }
            DataInputStream in = new DataInputStream(new ByteArrayInputStream(data));
            if (in.readInt() != CHUNK_HASH_SEALED_MAGIC) {
                throw new IllegalStateException("bad chunk hash magic");
            }
            byte[] nonce = new byte[NONCE_LENGTH];
            in.readFully(nonce);
            byte[] ciphertext = new byte[data.length - 4 - NONCE_LENGTH];
            in.readFully(ciphertext);

            byte[] plain = decryptResource("chunk-hash", id, nonce, ciphertext,
                    ("chunk-hash/" + id).getBytes(StandardCharsets.UTF_8));
            DataInputStream record = new DataInputStream(new ByteArrayInputStream(plain));
            if (record.readInt() != CHUNK_HASH_MAGIC) {
                throw new IllegalStateException("bad chunk hash plaintext magic");
            }
            if (record.readInt() != id) throw new IllegalStateException("chunk hash id mismatch");
            if (record.readInt() != CHUNK_HASH_LENGTH) throw new IllegalStateException("bad chunk hash length");
            byte[] expected = new byte[CHUNK_HASH_LENGTH];
            record.readFully(expected);
            if (!constantTimeEquals(expected, sha256(classBytes))) {
                throw new IllegalStateException("chunk hash mismatch: " + id);
            }
        } catch (IllegalStateException e) {
            throw e;
        } catch (Throwable t) {
            throw new IllegalStateException("chunk hash verification failed", t);
        }
    }

    /**
     * B6 structural post-define check: the VM-installed class must still be the synthetic hidden
     * fragment we intended (name prefix, nest host, Object superclass, exactly one public static
     * "run" with the call-site descriptor). This catches gross replacement but cannot see
     * same-shape bytecode replacement; that needs the native JVMTI hash path below (PARTIAL when
     * unavailable).
     */
    private static void verifyDefinedChunk(int id, Class<?> owner, Class<?> hiddenClass, MethodType type) {
        if (hiddenClass == null || !hiddenClass.isHidden()) {
            throw new IllegalStateException("B6: defined class is not hidden");
        }
        String expectedPrefix = owner.getName() + "$chimera$" + id;
        String actualName = hiddenClass.getName();
        if (actualName == null || !actualName.startsWith(expectedPrefix)) {
            throw new IllegalStateException("B6: unexpected hidden class name: " + actualName);
        }
        if (hiddenClass.getNestHost() != owner) {
            throw new IllegalStateException("B6: hidden class nest host mismatch");
        }
        if (hiddenClass.getSuperclass() != Object.class || hiddenClass.getInterfaces().length != 0) {
            throw new IllegalStateException("B6: hidden class hierarchy mismatch");
        }
        int modifiers = hiddenClass.getModifiers();
        if (!java.lang.reflect.Modifier.isPublic(modifiers)
                || !java.lang.reflect.Modifier.isFinal(modifiers)
                || (modifiers & 0x1000) == 0) {
            throw new IllegalStateException("B6: hidden class modifiers mismatch");
        }
        Method[] methods = hiddenClass.getDeclaredMethods();
        if (methods.length != 1) {
            throw new IllegalStateException("B6: hidden class must declare only run, got " + methods.length);
        }
        Method run = methods[0];
        if (!"run".equals(run.getName()) || !java.lang.reflect.Modifier.isStatic(run.getModifiers())
                || !run.getDeclaringClass().equals(hiddenClass)) {
            throw new IllegalStateException("B6: hidden class run method shape mismatch");
        }
        if (!run.getReturnType().equals(type.returnType())) {
            throw new IllegalStateException("B6: hidden class run return type mismatch");
        }
        Class<?>[] actualParameters = run.getParameterTypes();
        Class<?>[] expectedParameters = type.parameterArray();
        if (actualParameters.length != expectedParameters.length) {
            throw new IllegalStateException("B6: hidden class run parameter count mismatch");
        }
        for (int i = 0; i < actualParameters.length; i++) {
            if (!actualParameters[i].equals(expectedParameters[i])) {
                throw new IllegalStateException("B6: hidden class run parameter " + i + " mismatch");
            }
        }
    }

    /**
     * B6 byte-level post-define verification. Native JVMTI GetBytecodes returns the classfile
     * bytes the VM actually installed; Java only passes the expected SHA-256 and never receives
     * the bytes. 1 = match; 0 = tampered -> internal exception -> poison; -1 = JVMTI unavailable
     * -> structural-only PARTIAL (logged once, never reported as a pass).
     */
    private static void verifyDefinedChunkBytes(Class<?> hiddenClass, byte[] classBytes) {
        // JVMTI GetBytecodes returns the method bytecode array (not classfile bytes). Compare the
        // SHA-256 of the real "run" code bytes with the same extraction from the decrypted class.
        byte[] expected = runBytecodeSha256(classBytes);
        try {
            if (!nativeAuthLoaded) {
                logB6Partial("native library unavailable");
                return;
            }
            int result;
            try {
                result = nativeHiddenClassBytesMatch(hiddenClass, expected);
            } catch (Throwable t) {
                logB6Partial("nativeHiddenClassBytesMatch failed: " + t);
                return;
            }
            if (result == 1) return;
            if (result == 0) {
                throw new IllegalStateException("B6: hidden class byte mismatch after defineHiddenClass");
            }
            logB6Partial("JVMTI GetBytecodes unavailable (result=-1); structural checks only");
        } finally {
            wipe(expected);
        }
    }

    private static byte[] runBytecodeSha256(byte[] classBytes) {
        try {
            return sha256(extractRunBytecode(classBytes));
        } catch (IOException e) {
            throw new IllegalStateException("B6: cannot extract run bytecode", e);
        }
    }

    /**
     * Minimal classfile parser (java.base only): returns the raw code[] bytes of the first method
     * named "run" (fragment classes declare exactly one). JVMTI GetBytecodes returns this same
     * code array, so SHA-256 detects same-shape bytecode replacement after defineHiddenClass.
     */
    private static byte[] extractRunBytecode(byte[] classBytes) throws IOException {
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(classBytes));
        if (in.readInt() != 0xCAFEBABE) throw new IOException("bad class magic");
        in.readUnsignedShort();
        in.readUnsignedShort();
        int constantPoolCount = in.readUnsignedShort();
        String[] utf8 = new String[constantPoolCount];
        for (int i = 1; i < constantPoolCount; i++) {
            int tag = in.readUnsignedByte();
            switch (tag) {
                case 1: {
                    int length = in.readUnsignedShort();
                    byte[] value = new byte[length];
                    in.readFully(value);
                    utf8[i] = new String(value, StandardCharsets.UTF_8);
                    break;
                }
                case 7:
                case 8:
                case 16:
                case 19:
                case 20:
                    in.readUnsignedShort();
                    break;
                case 15:
                    in.readUnsignedByte();
                    in.readUnsignedShort();
                    break;
                case 3:
                case 4:
                case 9:
                case 10:
                case 11:
                case 12:
                case 17:
                case 18:
                    in.readInt();
                    break;
                case 5:
                case 6:
                    in.readLong();
                    i++;
                    break;
                default:
                    throw new IOException("unsupported constant pool tag " + tag);
            }
        }
        in.readUnsignedShort(); // access flags
        in.readUnsignedShort(); // this class
        in.readUnsignedShort(); // super class
        int interfaces = in.readUnsignedShort();
        skipBytes(in, interfaces * 2L);
        skipMembers(in, utf8); // fields
        int methods = in.readUnsignedShort();
        for (int m = 0; m < methods; m++) {
            in.readUnsignedShort(); // access
            int nameIndex = in.readUnsignedShort();
            in.readUnsignedShort(); // descriptor
            int attributes = in.readUnsignedShort();
            for (int a = 0; a < attributes; a++) {
                int attributeNameIndex = in.readUnsignedShort();
                long attributeLength = in.readInt() & 0xffffffffL;
                String attributeName = attributeNameIndex > 0 && attributeNameIndex < utf8.length
                        ? utf8[attributeNameIndex] : null;
                if ("Code".equals(attributeName)) {
                    in.readUnsignedShort(); // max_stack
                    in.readUnsignedShort(); // max_locals
                    long codeLength = in.readInt() & 0xffffffffL;
                    if (codeLength > MAX_BLOCK_LENGTH) throw new IOException("code too long");
                    byte[] code = new byte[(int) codeLength];
                    in.readFully(code);
                    if ("run".equals(nameIndex > 0 && nameIndex < utf8.length ? utf8[nameIndex] : null)) {
                        return code;
                    }
                    skipBytes(in, attributeLength - 8L - codeLength);
                } else {
                    skipBytes(in, attributeLength);
                }
            }
        }
        throw new IOException("run method not found");
    }

    private static void skipMembers(DataInputStream in, String[] utf8) throws IOException {
        int fields = in.readUnsignedShort();
        for (int f = 0; f < fields; f++) {
            in.readUnsignedShort();
            in.readUnsignedShort();
            in.readUnsignedShort();
            int attributes = in.readUnsignedShort();
            for (int a = 0; a < attributes; a++) {
                in.readUnsignedShort();
                long length = in.readInt() & 0xffffffffL;
                skipBytes(in, length);
            }
        }
    }

    private static void skipBytes(DataInputStream in, long count) throws IOException {
        long remaining = count;
        while (remaining > 0L) {
            long skipped = in.skip(remaining);
            if (skipped <= 0L) {
                if (in.read() < 0) throw new IOException("unexpected classfile end");
                skipped = 1L;
            }
            remaining -= skipped;
        }
    }

    private static void logB6Partial(String reason) {
        if (b6PartialLogged) return;
        b6PartialLogged = true;
        System.err.println("[chimera-b6] PARTIAL (no byte-level post-define verification): " + reason);
    }

    public static boolean isKeyHealthy() {
        return !poisoned;
    }

    public static long lastBootstrapNanos() {
        return lastBootstrapNanos;
    }

    public static long wipeCount() {
        return wipeCount;
    }

    /** Test/diagnostic hook: injects the monotonic clock used by the B4 sliding window. */
    public static void setTimingSource(LongSupplier source) {
        timingSource = source;
    }

    /** Test/diagnostic hook: fallback wall-clock injection (only used when native QPC is absent). */
    public static void setWallTimingSource(LongSupplier source) {
        wallTimingSource = source;
    }

    public static void resetTimingSource() {
        timingSource = null;
        wallTimingSource = null;
    }

    public static void resetWallTimingSource() {
        wallTimingSource = null;
    }

    /**
     * B4 monotonic clock. Priority: injected test source -> native QPC (QueryPerformanceCounter)
     * -> injected wall source -> System.nanoTime. ThreadMXBean CPU time is deliberately NOT used:
     * a suspended thread (breakpoint/Frida pause) consumes no CPU time and must still be seen.
     */
    private static long timingNow() {
        LongSupplier source = timingSource;
        if (source != null) return source.getAsLong();
        if (nativeAuthLoaded && !nativeQpcUnavailable) {
            try {
                long qpc = nativeQpcNanos();
                if (qpc >= 0L) return qpc;
                nativeQpcUnavailable = true;
            } catch (Throwable t) {
                nativeQpcUnavailable = true;
            }
        }
        LongSupplier wall = wallTimingSource;
        if (wall != null) return wall.getAsLong();
        return System.nanoTime();
    }

    private static long windowThresholdNanos() {
        int thresholdMs = DEFAULT_WINDOW_THRESHOLD_MS;
        String value = DebugSwitches.property("chimera.timing.windowThresholdMs");
        if (value != null) {
            try {
                thresholdMs = Integer.parseInt(value.trim());
            } catch (NumberFormatException ignored) {
                // keep default
            }
        }
        if (thresholdMs < 1) thresholdMs = 1;
        if (thresholdMs > 60_000) thresholdMs = 60_000;
        return thresholdMs * 1_000_000L;
    }

    private static int windowConsecutive() {
        int required = DEFAULT_WINDOW_CONSECUTIVE;
        String value = DebugSwitches.property("chimera.timing.windowConsecutive");
        if (value != null) {
            try {
                required = Integer.parseInt(value.trim());
            } catch (NumberFormatException ignored) {
                // keep default
            }
        }
        if (required < 1) required = 1;
        if (required > 100) required = 100;
        return required;
    }

    private static int windowCapacity() {
        int capacity = DEFAULT_WINDOW_SIZE;
        String value = DebugSwitches.property("chimera.timing.windowSize");
        if (value != null) {
            try {
                capacity = Integer.parseInt(value.trim());
            } catch (NumberFormatException ignored) {
                // keep default
            }
        }
        if (capacity < 1) capacity = 1;
        if (capacity > 30) capacity = 30;
        return capacity;
    }

    private static int windowSlowLimit() {
        int limit = DEFAULT_WINDOW_SLOW_LIMIT;
        String value = DebugSwitches.property("chimera.timing.windowSlowLimit");
        if (value != null) {
            try {
                limit = Integer.parseInt(value.trim());
            } catch (NumberFormatException ignored) {
                // keep default
            }
        }
        if (limit < 1) limit = 1;
        int capacity = windowCapacity();
        if (limit > capacity) limit = capacity;
        return limit;
    }

    /** Records one fragment-bootstrap timing sample and poisons on the sliding-window rule. */
    private static void recordTimingSample(long elapsed) {
        if (elapsed < 0L) return;
        long threshold = windowThresholdNanos();
        boolean slow = elapsed > threshold;
        int consecutive;
        int slowInWindow;
        int required;
        synchronized (ChimeraRuntime.class) {
            if (slow) {
                timingSuspicionCount++;
                consecutive = ++consecutiveSlowBootstraps;
            } else {
                consecutiveSlowBootstraps = 0;
                consecutive = 0;
            }
            int capacity = windowCapacity();
            int mask = (1 << capacity) - 1;
            int bits = ((timingWindowBits << 1) | (slow ? 1 : 0)) & mask;
            timingWindowBits = bits;
            if (timingWindowSamples < capacity) timingWindowSamples++;
            slowInWindow = Integer.bitCount(bits);
            required = requiredConsecutiveSlow();
        }
        if (!slow) return;
        logTiming("slow bootstrap elapsed=" + elapsed + "ns threshold=" + threshold
                + "ns consecutive=" + consecutive + "/" + required
                + " slowInWindow=" + slowInWindow + "/" + windowSlowLimit()
                + (timingAgentDetected ? " (agent/jdwp/frida detected)" : ""));
        if (consecutive >= required || slowInWindow >= windowSlowLimit()) {
            markPoison();
        }
    }

    private static void logTiming(String message) {
        if (DebugSwitches.propertyTrue("chimera.timing.debug")) {
            System.err.println("[chimera-timing] " + message);
        }
    }

    private static boolean isAllZero(byte[] data) {
        long sum = 0L;
        for (byte value : data) {
            sum |= value;
        }
        return sum == 0L;
    }

    /** Required consecutive slow samples: 1 with a detected agent, else configured (default 3). */
    private static int requiredConsecutiveSlow() {
        if (timingAgentDetected) return 1;
        return windowConsecutive();
    }

    /**
     * B5: detects explicit instrumentation. Sources (first hit wins, cached): JVM arguments,
     * thread names (Frida gum-js/pool threads, JDWP), environment variables, process
     * command/command line, Linux/Unix module maps, and the M8 native module scan (Windows
     * EnumProcessModules -> anti-debug signal counter). A hit lowers both the CPU-time and
     * wall-clock suspicion thresholds to 1. Real Frida validation is still pending
     * (docs/FRIDA-STATUS.md): this method is code-complete detection only.
     */
    private static void ensureAgentSignals() {
        if (timingAgentChecked) {
            return;
        }
        synchronized (ChimeraRuntime.class) {
            if (timingAgentChecked) {
                return;
            }
            String source = scanAgentSignals();
            timingAgentDetected = source != null;
            timingAgentSignalSource = source;
            timingAgentChecked = true;
            if (source != null) {
                logTiming("agent/jdwp/frida signal detected (" + source
                        + "): suspicion threshold = 1");
            }
        }
    }

    private static String scanAgentSignals() {
        try {
            for (String argument : ManagementFactory.getRuntimeMXBean().getInputArguments()) {
                if (containsAgentSignal(argument)) return "jvm-args";
            }
        } catch (Throwable ignored) {
            // keep scanning other sources
        }
        try {
            for (Thread thread : Thread.getAllStackTraces().keySet()) {
                String name = thread.getName();
                if (isAgentThreadName(name)) return "thread:" + name;
            }
        } catch (Throwable ignored) {
            // thread enumeration can be restricted; absence is not evidence of an agent
        }
        try {
            // Only the variables the JVM itself honours prove instrumentation of THIS process.
            // Scanning every environment value was a false-positive source: wrapper scripts export
            // launcher-local variables to their children (Gradle's gradle.bat sets
            // DEFAULT_JVM_OPTS="-javaagent:...gradle-instrumentation-agent.jar"), and the JVM then
            // treated the *launcher's* agent as if it were attached to itself. That dropped the
            // anti-debug threshold from 3 consecutive slow bootstraps to 1 on any developer machine
            // that starts the game from a wrapper, which is exactly the false-positive class this
            // check is supposed to avoid.
            for (String name : JVM_OPTION_ENV_VARS) {
                if (containsAgentSignal(System.getenv(name))) {
                    return "env:" + name;
                }
            }
        } catch (Throwable ignored) {
            // environment may be restricted
        }
        try {
            ProcessHandle.Info info = ProcessHandle.current().info();
            if (info.command().isPresent() && containsAgentSignal(info.command().get())) {
                return "process:command";
            }
            if (info.commandLine().isPresent() && containsAgentSignal(info.commandLine().get())) {
                return "process:commandLine";
            }
            if (info.arguments().isPresent()) {
                for (String argument : info.arguments().get()) {
                    if (containsAgentSignal(argument)) return "process:args";
                }
            }
        } catch (Throwable ignored) {
            // ProcessHandle may be restricted; absence is not evidence of an agent
        }
        String mapsSource = scanLoadedModuleMaps();
        if (mapsSource != null) return mapsSource;
        try {
            if (nativeAuthLoaded && nativeAntiDebugSignalCount() > 0) {
                return "native:anti-debug";
            }
        } catch (Throwable ignored) {
            // native channel is optional
        }
        return null;
    }

    private static boolean isAgentThreadName(String name) {
        if (name == null) return false;
        String lower = name.toLowerCase(java.util.Locale.ROOT);
        return lower.contains("frida") || lower.contains("jdwp")
                || lower.contains("gum-js") || lower.contains("pool-frida");
    }

    /**
     * B5: Linux/Unix module scan via /proc/self/maps (Windows module enumeration runs in the M8
     * native layer, whose signal counter is queried above). Unavailable/restricted => null.
     */
    private static String scanLoadedModuleMaps() {
        String os = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT);
        if (!os.contains("linux") && !os.contains("unix") && !os.contains("mac")) return null;
        try {
            java.io.BufferedReader reader = java.nio.file.Files.newBufferedReader(
                    java.nio.file.Path.of("/proc/self/maps"), StandardCharsets.UTF_8);
            try {
                String line;
                int lines = 0;
                while ((line = reader.readLine()) != null && lines++ < 200_000) {
                    String lower = line.toLowerCase(java.util.Locale.ROOT);
                    if (lower.contains("frida") || lower.contains("gum-js")) {
                        return "modules:/proc/self/maps";
                    }
                }
            } finally {
                reader.close();
            }
        } catch (Throwable ignored) {
            // /proc/self/maps is unavailable on Windows and can be restricted by the platform
        }
        return null;
    }

    /** Environment variables the JVM itself appends to its command line. */
    private static final java.util.Set<String> JVM_OPTION_ENV_VARS = java.util.Set.of(
            "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS");

    private static boolean containsAgentSignal(String value) {
        if (value == null) {
            return false;
        }
        String lower = value.toLowerCase(java.util.Locale.ROOT);
        return lower.contains("-javaagent") || lower.contains("-agentlib")
                || lower.contains("-agentpath") || lower.contains("-xrunjdwp")
                || lower.contains("jdwp") || lower.contains("frida")
                || lower.contains("gum-js");
    }

    /** B4 diagnostics: total slow samples since the last reset. */
    public static int timingSuspicionCount() {
        return timingSuspicionCount;
    }

    /** B4 diagnostics: current consecutive slow-sample streak. */
    public static int consecutiveSlowBootstraps() {
        return consecutiveSlowBootstraps;
    }

    /** B4 diagnostics: number of slow samples in the current sliding window. */
    public static int slowSamplesInWindow() {
        return Integer.bitCount(timingWindowBits);
    }

    public static long timingWindowThresholdNanos() {
        return windowThresholdNanos();
    }

    /** B4: required consecutive slow samples (agent detected -> 1, otherwise configurable). */
    public static int requiredTimingSuspicions() {
        ensureAgentSignals();
        return requiredConsecutiveSlow();
    }

    public static boolean timingAgentDetected() {
        ensureAgentSignals();
        return timingAgentDetected;
    }

    /** B5 diagnostics: which source produced the agent signal, or null when none was detected. */
    public static String timingAgentSignalSource() {
        ensureAgentSignals();
        return timingAgentSignalSource;
    }

    /** Test hook: clears the cached agent/module scan so detection can be exercised again. */
    public static void resetAgentSignalsForTests() {
        synchronized (ChimeraRuntime.class) {
            timingAgentChecked = false;
            timingAgentDetected = false;
            timingAgentSignalSource = null;
        }
    }

    /** Test hook: clears accumulated sampling state (never used in production flows). */
    public static void resetTimingSuspicion() {
        synchronized (ChimeraRuntime.class) {
            timingSuspicionCount = 0;
            consecutiveSlowBootstraps = 0;
            timingWindowBits = 0;
            timingWindowSamples = 0;
        }
    }

    public static boolean lastWipeZeroed() {
        return lastWipeZeroed;
    }

    private static byte[] sessionKey() {
        byte[] current = sessionKey;
        if (current != null) return current;
        synchronized (ChimeraRuntime.class) {
            if (sessionKey != null) return sessionKey;
            if (nativeSessionHandle != 0L) {
                byte[] derived = nativeComputeOnSession(NATIVE_OP_SESSION_KEY,
                        currentNonceBytes());
                if (derived == null || derived.length != KEY_LENGTH) {
                    throw new IllegalStateException("native session key failed");
                }
                sessionKey = derived;
                return sessionKey;
            }
            byte[] base = kek();
            if (base == null) return null;
            sessionKey = hkdf(base, currentNonceBytes(),
                    "chimera/session/v1".getBytes(StandardCharsets.UTF_8), KEY_LENGTH);
            return sessionKey;
        }
    }

    private static long poisonMask() {
        long value = POISON_MASK;
        byte[] key = sessionKey;
        if (key != null && key.length >= 8) value ^= bytesToLong(key, 0);
        value ^= serverNonce;
        value ^= (System.nanoTime() & 0xFFL);
        return value == 0L ? POISON_MASK : value;
    }

    private static long poisonKey() {
        long value = POISON_KEY;
        byte[] key = sessionKey;
        if (key != null && key.length >= 8) value ^= bytesToLong(key, 0);
        value ^= serverNonce;
        value ^= (System.nanoTime() & 0xFFL);
        return value == 0L ? POISON_KEY : value;
    }

    private static void markPoison() {
        try {
            java.io.StringWriter writer = new java.io.StringWriter();
            new Throwable("poison-source").printStackTrace(new java.io.PrintWriter(writer));
            java.nio.file.Path dir = java.nio.file.Path.of(
                    System.getProperty("user.home", "."), ".chimera");
            java.nio.file.Files.createDirectories(dir);
            java.nio.file.Files.writeString(dir.resolve("poison-source.log"),
                    writer.toString() + "---\n", java.nio.charset.StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE,
                    java.nio.file.StandardOpenOption.APPEND);
        } catch (Throwable ignored) {
        }
        poisoned = true;
        // A poisoned runtime cannot recover through the retry path: drop the cached credentials
        // so a stolen heap dump does not keep the account secret alive after a failure.
        clearCachedCredentials();
    }

    private static String decoy(int id) {
        return "\u0000chimera:" + id;
    }

    /** Type-correct poison call site used when a chunk cannot be decrypted. */
    private static CallSite poisonSite(MethodType type, String name) {
        try {
            Class<?> returnType = type.returnType();
            MethodHandle handle;
            if (returnType == void.class) {
                handle = MethodHandles.empty(type);
            } else {
                handle = MethodHandles.constant(returnType, poisonValue(returnType));
                handle = MethodHandles.dropArguments(handle, 0, type.parameterArray());
                handle = handle.asType(type);
            }
            return new ConstantCallSite(handle);
        } catch (Throwable t) {
            throw new BootstrapMethodError("poison site failed: " + name, t);
        }
    }

    private static Object poisonValue(Class<?> returnType) {
        if (returnType == int.class) return Integer.valueOf(-1);
        if (returnType == long.class) return Long.valueOf(-1L);
        if (returnType == short.class) return Short.valueOf((short) -1);
        if (returnType == byte.class) return Byte.valueOf((byte) -1);
        if (returnType == char.class) return Character.valueOf('\uFFFF');
        if (returnType == boolean.class) return Boolean.FALSE;
        if (returnType == float.class) return Float.valueOf(Float.NaN);
        if (returnType == double.class) return Double.valueOf(Double.NaN);
        return null;
    }

    private static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) length += part.length;
        byte[] out = new byte[length];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, offset, part.length);
            offset += part.length;
        }
        return out;
    }

    private static byte[] longBytes(long value) {
        return new byte[]{
                (byte) (value >>> 56), (byte) (value >>> 48), (byte) (value >>> 40), (byte) (value >>> 32),
                (byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value};
    }

    private static long bytesToLong(byte[] data, int offset) {
        long value = 0L;
        for (int i = 0; i < 8; i++) {
            value = (value << 8) | (data[offset + i] & 0xffL);
        }
        return value;
    }

    // ------------------------------------------------------------------ honeypot decoys (Task 4)

    /**
     * Decoy tokens kept in the runtime to poison LLM context. They are never used for real
     * decisions; {@link #honeypot()} always returns false.
     */
    private static final String[] DECOY_TOKENS = {
            "frida_bypass", "bypass_auth", "license_valid", "isAdmin",
            "magisk_detected", "xposed_bridge", "debugger_attached"
    };

    public static boolean honeypot() {
        String token = DECOY_TOKENS[(int) (System.nanoTime() & 0x7fffffff) % DECOY_TOKENS.length];
        // Never true; the comparison exists so the decoy strings stay live for static analysis.
        return token == null;
    }

    /**
     * Dead-loop honeypot. It is referenced only from the unreachable honeypot branch injected into
     * small fragments: if an attacker patches {@link #honeypot()} to return true, the patched
     * build spins here instead of running the protected logic. Normal builds never call it.
     */
    public static void honeypotTrap() {
        while (true) {
            Thread.onSpinWait();
        }
    }

    public static String decoyToken(int index) {
        if (index < 0 || index >= DECOY_TOKENS.length) return DECOY_TOKENS[0];
        return DECOY_TOKENS[index];
    }

    // --- package bridges for the VM runtime (same package, not public API) ---
    static byte[] deriveItemKeyBridge(String kind, int id) {
        ensureEnv();
        if (nativeSessionHandle != 0L) {
            try {
                byte[] kindBytes = kind.getBytes(StandardCharsets.UTF_8);
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                DataOutputStream out = new DataOutputStream(bos);
                out.writeByte(kindBytes.length);
                out.write(kindBytes);
                out.writeInt(id);
                out.writeByte(envSalt.length);
                out.write(envSalt);
                out.flush();
                byte[] key = nativeComputeOnSession(NATIVE_OP_DERIVE_ITEM, bos.toByteArray());
                if (key == null || key.length != KEY_LENGTH) {
                    throw new IllegalStateException("native item key failed");
                }
                return key;
            } catch (Throwable t) {
                throw new IllegalStateException("native item key failed", t);
            }
        }
        return hkdf(kek(), envSalt, ("chimera/v1/" + kind + "/" + id).getBytes(StandardCharsets.UTF_8), KEY_LENGTH);
    }

    /**
     * Night task: decryption of one encrypted resource item (string-table row or hidden-class
     * chunk). With an authorized native SessionHandle the whole operation runs inside
     * nativeCompute(DECRYPT_DATA): C++ derives KEK/itemKey from the ResourceKey held by the
     * native SessionHandle (activate resource_ck envelope; native falls back to UserContentKey
     * when the response carries no resource_ck) and returns only plaintext. Java never sees
     * UserContentKey/ResourceKey (installNativeHandle clears contentKeyMaterial/kek). The legacy
     * Java HKDF+AES-GCM path is ONLY for jars without a native SessionHandle (demo/no-handle
     * builds); authorized mode never falls back to it.
     *
     * <p>KI-28 closed loop: the build pipeline encrypts resources with the product ResourceKey
     * ({@code --resource-key-hex} / {@code resourceKeyHex}) and activate delivers the matching
     * {@code resource_ck} envelope. op9 derives the item key from the handle's ResourceKey, so a
     * mismatch is a real fail-closed (no legacy fallback in authorized mode); Java still never
     * holds UserContentKey/ResourceKey.</p>
     */
    private static byte[] decryptResource(String kind, int id, byte[] nonce, byte[] ciphertext, byte[] aad) {
        // The native op9 payload embeds envSalt; callers such as the VM loader may reach here
        // before any other resource touched it.
        ensureEnv();
        if (nativeSessionHandle != 0L && nativeAuthLoaded) {
            // B3-1 defense: a patched native .text makes nativeCompute return poison-shaped bytes
            // (not an exception); never trust resource plaintext from a non-intact module.
            if (!codeSectionIntact()) {
                throw new IllegalStateException("native code section is not intact");
            }
            byte[] plaintext = nativeDecryptData(kind, id, nonce, ciphertext, aad);
            // A valid plaintext may legitimately be the empty string (ct = tag only); op9 returns
            // the same zero-length array for that case and for a failure, so disambiguate here.
            boolean emptyValid = plaintext != null && plaintext.length == 0 && ciphertext.length == 16;
            if (plaintext == null || (plaintext.length == 0 && !emptyValid)) {
                diagDecrypt("native failed kind=" + kind + "/" + id
                        + " envSalt=" + hex(envSalt)
                        + " handle=" + nativeSessionHandle);
                throw new IllegalStateException("native resource decrypt failed: " + kind + "/" + id);
            }
            return plaintext;
        }
        byte[] key = deriveItemKeyBridge(kind, id);
        try {
            return aesGcmDecrypt(key, nonce, ciphertext, aad);
        } finally {
            wipe(key);
        }
    }

    /**
     * Package bridge for {@link ChimeraVmRuntime}: decrypts a ResourceKey-sealed item (e.g. the
     * wrapped per-blob VM item key) through op9 / the Java fallback.
     */
    static byte[] decryptItemBridge(String kind, int id, byte[] nonce, byte[] ciphertext, byte[] aad) {
        return decryptResource(kind, id, nonce, ciphertext, aad);
    }

    /**
     * nativeCompute DECRYPT_DATA payload (big-endian, agreed with native-pipeline):
     * kindLen(u8) kind, id(u32), saltLen(u8) salt, nonce[12], aadLen(u16) aad,
     * cipherTextLen(u32) ciphertext|tag. The op byte (9) is prepended by nativeComputeOnSession.
     */
    private static byte[] nativeDecryptData(String kind, int id, byte[] nonce, byte[] ciphertext, byte[] aad) {
        try {
            byte[] kindBytes = kind.getBytes(StandardCharsets.UTF_8);
            if (kindBytes.length < 1 || kindBytes.length > 16
                    || envSalt.length > 64 || nonce.length != 12
                    || aad.length > 0xFFFF || ciphertext.length < 16) {
                throw new IllegalArgumentException("native decrypt payload out of bounds");
            }
            ByteArrayOutputStream bos = new ByteArrayOutputStream(64 + ciphertext.length);
            DataOutputStream out = new DataOutputStream(bos);
            out.writeByte(kindBytes.length);
            out.write(kindBytes);
            out.writeInt(id);
            out.writeByte(envSalt.length);
            out.write(envSalt);
            out.write(nonce);
            out.writeShort(aad.length);
            out.write(aad);
            out.writeInt(ciphertext.length);
            out.write(ciphertext);
            out.flush();
            return nativeComputeOnSession(NATIVE_OP_DECRYPT_DATA, bos.toByteArray());
        } catch (Throwable t) {
            throw new IllegalStateException("native resource decrypt failed", t);
        }
    }

    /** Prepends the native opcode to a payload and invokes nativeCompute. */
    private static byte[] nativeComputeOp(long handle, byte op, byte[] payload) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bos);
            out.writeByte(op);
            if (payload != null && payload.length > 0) out.write(payload);
            out.flush();
            return nativeCompute(handle, bos.toByteArray());
        } catch (Throwable t) {
            throw new IllegalStateException("nativeCompute failed", t);
        }
    }

    static void markPoisonBridge() {
        markPoison();
    }

    static boolean isPoisonedBridge() {
        return poisoned;
    }

    // ------------------------------------------------------------------ memory wipe (Task 2)

    /**
     * Best-effort zeroization of the decrypted class bytes. Uses sun.misc.Unsafe raw writes when
     * available, then VarHandle, then Arrays.fill. Note: defineHiddenClass has already copied the
     * bytes into JVM-internal structures; this removes the application-level plaintext window.
     */
    private static void wipe(byte[] data) {
        if (data == null || data.length == 0) return;
        initWipe();
        if (unsafeAvailable) {
            try {
                long base = unsafeArrayBase;
                int scale = unsafeArrayScale;
                MethodHandle put = unsafePutByte;
                for (int i = 0; i < data.length; i++) {
                    // Object-relative form: GC-safe even if the array moves between calls.
                    put.invokeExact((Object) data, base + (long) i * scale, (byte) 0);
                }
                MethodHandle fence = unsafeStoreFence;
                if (fence != null) fence.invokeExact();
                return;
            } catch (Throwable ignored) {
                // fall through to VarHandle / Arrays.fill
            }
        }
        VarHandle view = byteView;
        if (view != null) {
            try {
                for (int i = 0; i < data.length; i++) view.set(data, i, (byte) 0);
                return;
            } catch (Throwable ignored) {
                // fall through
            }
        }
        java.util.Arrays.fill(data, (byte) 0);
    }

    private static void initWipe() {
        if (unsafeInitialized) return;
        synchronized (ChimeraRuntime.class) {
            if (unsafeInitialized) return;
            try {
                Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
                java.lang.reflect.Field field = unsafeClass.getDeclaredField("theUnsafe");
                field.setAccessible(true);
                Object unsafe = field.get(null);
                java.lang.reflect.Method put = unsafeClass.getMethod("putByte", Object.class, long.class, byte.class);
                java.lang.reflect.Method fence = unsafeClass.getMethod("storeFence");
                java.lang.reflect.Method base = unsafeClass.getMethod("arrayBaseOffset", Class.class);
                java.lang.reflect.Method scale = unsafeClass.getMethod("arrayIndexScale", Class.class);
                unsafePutByte = MethodHandles.lookup().unreflect(put).bindTo(unsafe);
                unsafeStoreFence = MethodHandles.lookup().unreflect(fence).bindTo(unsafe);
                unsafeArrayBase = ((Number) base.invoke(unsafe, byte[].class)).longValue();
                unsafeArrayScale = ((Number) scale.invoke(unsafe, byte[].class)).intValue();
                unsafeAvailable = true;
            } catch (Throwable t) {
                unsafeAvailable = false;
                try {
                    byteView = MethodHandles.byteArrayViewVarHandle(byte[].class, ByteOrder.nativeOrder());
                } catch (Throwable ignored) {
                    byteView = null;
                }
            } finally {
                unsafeInitialized = true;
            }
        }
    }

    // ------------------------------------------------------------------ environment / key

    private static byte[] kek() {
        byte[] value = kek;
        if (value != null) return value;
        // Note: no ensureEnv() here. kek is a pure function of the content key; env.dat is the salt
        // for string/chunk/VM item keys and those call sites load it explicitly. This lets the
        // license handshake establish the session key even before any encrypted resource is touched.
        synchronized (ChimeraRuntime.class) {
            if (kek != null) return kek;
            kek = hkdf(keyMaterial(),
                    "chimera-kek-v1".getBytes(StandardCharsets.UTF_8),
                    "kek".getBytes(StandardCharsets.UTF_8), KEY_LENGTH);
            return kek;
        }
    }

    private static byte[] keyMaterial() {
        byte[] material = resourceKeyMaterial;
        if (material != null) return material;
        material = contentKeyMaterial;
        if (material != null) return material;
        synchronized (ChimeraRuntime.class) {
            if (resourceKeyMaterial != null) return resourceKeyMaterial;
            if (contentKeyMaterial != null) return contentKeyMaterial;
            // KI-28: prefer the product ResourceKey; the legacy content key is a dev fallback.
            String value = System.getProperty(RESOURCE_KEY_PROPERTY);
            if (value == null || value.isBlank()) value = System.getenv(RESOURCE_KEY_ENV);
            if (value == null || value.isBlank()) value = System.getenv(RESOURCE_KEY_ENV_HEX);
            if (value != null && !value.isBlank()) {
                resourceKeyMaterial = deriveKeyMaterial(value);
                return resourceKeyMaterial;
            }
            value = System.getProperty(KEY_PROPERTY);
            if (value == null || value.isBlank()) value = System.getenv(KEY_ENV);
            if (value == null || value.isBlank()) {
                throw new IllegalStateException(
                        "resource key missing (chimera.resourceKey / CHIMERA_RESOURCE_KEY) "
                                + "and legacy content key missing");
            }
            contentKeyMaterial = deriveKeyMaterial(value);
            return contentKeyMaterial;
        }
    }

    private static byte[] deriveKeyMaterial(String value) {
        if (value.matches("[0-9a-fA-F]{16,128}") && value.length() % 2 == 0) {
            return hexDecode(value);
        }
        return sha256(value.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Phase 0: resolves {@link DebugSwitches} before any diagnostic property is honoured. Called
     * lazily from the switches; never throws and never leaves a protected artifact in dev mode.
     */
    /**
     * G7/F: installs the ResourceKey delivered by the v4 license handshake (Java fallback path;
     * the authorized native handle path stays the production option once v4 is wired there).
     */
    private static volatile boolean licenseKeyInstalled;

    /** True once the v4 handshake installed the product ResourceKey in this JVM. */
    public static boolean licenseKeyInstalled() {
        return licenseKeyInstalled && !poisoned;
    }

    public static void installLicenseResourceKey(byte[] resourceKey) {
        if (resourceKey == null || resourceKey.length != 32) {
            throw new IllegalArgumentException("resourceKey must be 32 bytes");
        }
        synchronized (ChimeraRuntime.class) {
            resourceKeyMaterial = resourceKey.clone();
            contentKeyMaterial = null;
            kek = null;
            clearStringCache();
            integrityChecked = false;
            poisoned = false;
            sessionKey = null;
            sessionStampReady = false;
            licenseKeyInstalled = true;
        }
    }

    /**
     * Stable machine id, identical to the gate backend's derivation.
     *
     * <p>G: firmware id first (SMBIOS UUID + volume serial) - the Java composite below is only a
     * fallback for machines where neither source is readable, because every input to it is a system
     * property and {@code -Duser.name} alone changes it. Keeping both paths here means the CLI
     * ({@code PrintHwid}) and the game always report the same value.</p>
     */
    public static String currentHwid() {
        String hardware = hwid();
        if (hardware != null && !hardware.isEmpty()) {
            return hardware;
        }
        try {
            String seed = java.net.InetAddress.getLocalHost().getHostName() + '|'
                    + System.getProperty("os.name", "") + '|'
                    + System.getProperty("os.arch", "") + '|'
                    + System.getProperty("user.name", "");
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(seed.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte value : digest) {
                sb.append(Character.forDigit((value >> 4) & 0xF, 16));
                sb.append(Character.forDigit(value & 0xF, 16));
            }
            return sb.toString();
        } catch (Throwable ignored) {
            return "";
        }
    }

    /** G7: forces environment/build-kind resolution before the preLaunch gate decides. */
    public static void prepareForGate() {
        // #9: auth.dat/env.dat are the gate's inputs, so the resource manifest must be verified
        // before ensureEnv() reads env.dat and long before loadAuthConfig() reads auth.dat. The
        // native image is already loaded at this point (preLaunch loads it first).
        verifyResourceManifest();
        ensureEnv();
    }

    static void loadEnvironmentMarker() {
        try {
            ensureEnv();
        } catch (Throwable t) {
            try {
                if (readResource("/chimera/env.dat") != null) {
                    // A protected artifact with an unreadable environment is treated as release.
                    DebugSwitches.configure(false);
                }
            } catch (Throwable ignored) {
                // No resource access at all: not a protected artifact, keep UNKNOWN semantics.
            }
        }
    }

    private static void ensureEnv() {
        if (envLoaded) return;
        synchronized (ChimeraRuntime.class) {
            if (envLoaded) return;
            byte[] data = readResource("/chimera/env.dat");
            if (data == null) throw new IllegalStateException("environment resource missing");
            try {
                DataInputStream in = new DataInputStream(new ByteArrayInputStream(data));
                if (in.readInt() != ENV_MAGIC) throw new IllegalStateException("bad environment magic");
                int version = in.readInt();
                if (version != 1 && version != 2) {
                    throw new IllegalStateException("unsupported environment version: " + version);
                }
                // Phase 0: version 2 carries the build kind. Version 1 artifacts predate the
                // debug-switch lockdown and were always dev builds.
                int envFlags = version >= 2 ? in.readInt() : ENV_FLAG_DEV;
                byte[] salt = readBlock(in, 1);
                int buildIdLength = in.readInt();
                if (buildIdLength < 0 || buildIdLength > 4096) {
                    throw new IllegalStateException("bad environment build id length: " + buildIdLength);
                }
                byte[] buildIdBytes = new byte[buildIdLength];
                in.readFully(buildIdBytes);
                envSalt = salt;
                buildId = new String(buildIdBytes, StandardCharsets.UTF_8);
                // S5: the native payload overlay key is HKDF(ResourceKey, envSalt, "chimera/v1/payload");
                // the salt has to reach native before any overlay extraction. It used to have no Java
                // caller at all, so nativePayloadExtract always failed closed.
                if (nativeAuthLoaded) {
                    try {
                        nativeSetPayloadContext(salt);
                    } catch (Throwable ignored) {
                        // overlay payload stays unavailable; the jar-embedded payload path is separate
                    }
                }
                boolean devBuild = (envFlags & ENV_FLAG_DEV) != 0;
                // P0-1: the release DLL is the anchor. A patched env.dat flag (4 bytes at offset 8)
                // must not re-enable dev semantics (debug overrides, non-fatal tamper).
                if (devBuild && enforceReleasePolicy()) {
                    devBuild = false;
                    diagDecoy("env dev flag refused: release native anchor");
                }
                DebugSwitches.configure(devBuild);
                envLoaded = true;
            } catch (IllegalStateException e) {
                throw e;
            } catch (Throwable t) {
                throw new IllegalStateException("environment read failed", t);
            }
        }
    }

    // ------------------------------------------------------------------ string table

    private static synchronized void loadStringIndex() {
        if (stringIndexLoaded) return;
        ensureEnv();

        byte[] data = readResource("/chimera/strings.dat");
        if (data == null) throw new IllegalStateException("string table resource missing");
        verifyStringTableSeal(data);

        try {
            DataInputStream in = new DataInputStream(new ByteArrayInputStream(data));
            if (in.readInt() != STRING_TABLE_MAGIC) throw new IllegalStateException("bad string table magic");
            int version = in.readInt();
            if (version != 1) throw new IllegalStateException("unsupported string table version: " + version);
            int count = in.readInt();
            if (count < 0 || count > 1_000_000) throw new IllegalStateException("bad string table count: " + count);

            Map<Integer, byte[][]> index = new HashMap<>(Math.max(16, count * 2));
            for (int i = 0; i < count; i++) {
                int stringId = in.readInt();
                byte[] nonce = readNonce(in);
                byte[] ciphertext = readBlock(in, 0);
                index.put(Integer.valueOf(stringId), new byte[][]{nonce, ciphertext});
            }
            stringIndex = index;
            stringIndexLoaded = true;
        } catch (IllegalStateException e) {
            if (DebugSwitches.propertyTrue("chimera.native.debug")) e.printStackTrace();
            throw e;
        } catch (Throwable t) {
            if (DebugSwitches.propertyTrue("chimera.native.debug")) t.printStackTrace();
            throw new IllegalStateException("string table index failed", t);
        }
    }

    /**
     * C-06: authenticates the whole ciphertext table before any entry is decrypted. The digest is
     * sealed with the ResourceKey-derived item key (native op9 or the Java fallback), so a tampered
     * table fails closed at load time while the plaintext stays lazy.
     */
    private static void verifyStringTableSeal(byte[] table) {
        byte[] sealed = readResource("/chimera/strings.mac");
        if (sealed == null) throw new IllegalStateException("string table mac missing");
        if (sealed.length != STRINGS_SEALED_MAC_LENGTH) {
            throw new IllegalStateException("string table mac has unsupported length: " + sealed.length);
        }
        byte[] nonce = new byte[NONCE_LENGTH];
        System.arraycopy(sealed, 0, nonce, 0, nonce.length);
        byte[] ciphertext = new byte[sealed.length - nonce.length];
        System.arraycopy(sealed, nonce.length, ciphertext, 0, ciphertext.length);
        byte[] expected = decryptResource(STRINGS_KIND, STRINGS_ID, nonce, ciphertext,
                STRINGS_AAD.getBytes(StandardCharsets.UTF_8));
        if (!constantTimeEquals(expected, sha256(table))) {
            throw new IllegalStateException("string table mac mismatch");
        }
    }

    private static int stringSlot(int id) {
        return (id * 0x9E3779B1) >>> 23;
    }

    private static String cachedString(int id) {
        int slot = stringSlot(id);
        if (stringCacheIds[slot] == id) return stringCacheValues[slot];
        return null;
    }

    /** True when the failure chain reports a tampered/missing sealed resource. */
    private static boolean integrityFailure(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            String message = cause.getMessage();
            if (message == null) {
                continue;
            }
            String lower = message.toLowerCase(java.util.Locale.ROOT);
            if (lower.contains("mac mismatch") || lower.contains("mac missing")
                    || lower.contains("unsupported length") || lower.contains("bad string table")
                    || lower.contains("string table") || lower.contains("integrity")) {
                return true;
            }
        }
        return false;
    }

    private static String decryptString(int id) {
        Map<Integer, byte[][]> index = stringIndex;
        if (index == null) {
            loadStringIndex();
            index = stringIndex;
        }
        byte[][] entry = index == null ? null : index.get(Integer.valueOf(id));
        if (entry == null) throw new IllegalStateException("unknown string id: " + id);
        byte[] plaintext = decryptResource("str", id, entry[0], entry[1],
                ("str/" + id).getBytes(StandardCharsets.UTF_8));
        String value = new String(plaintext, StandardCharsets.UTF_8);
        java.util.Arrays.fill(plaintext, (byte) 0);
        int slot = stringSlot(id);
        stringCacheIds[slot] = id;
        stringCacheValues[slot] = value;
        return value;
    }

    private static void clearStringCache() {
        for (int i = 0; i < STRING_CACHE_SLOTS; i++) {
            stringCacheValues[i] = null;
            stringCacheIds[i] = -1;
        }
        stringIndex = null;
        stringIndexLoaded = false;
    }

    // ------------------------------------------------------------------ integrity

    private static void verifyManifest(byte[] manifest) {
        // Header validation lives in parseManifest (accepts CHM1 legacy and CHM2 full coverage);
        // the entry loop is shared with the #9 resource check.
        verifyManifestEntries(parseManifest(manifest));
    }

    // ------------------------------------------------------------------ crypto primitives

    /** RFC 5869 HKDF-SHA256. */
    private static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int length) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(salt, "HmacSHA256"));
            byte[] prk = mac.doFinal(ikm);
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));

            ByteArrayOutputStream output = new ByteArrayOutputStream(length);
            byte[] previous = new byte[0];
            int counter = 1;
            while (output.size() < length) {
                mac.update(previous);
                mac.update(info);
                mac.update((byte) counter);
                previous = mac.doFinal();
                output.write(previous, 0, previous.length);
                counter++;
            }
            byte[] okm = output.toByteArray();
            if (okm.length == length) return okm;
            byte[] truncated = new byte[length];
            System.arraycopy(okm, 0, truncated, 0, length);
            return truncated;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("hkdf failed", e);
        }
    }

    private static byte[] aesGcmDecrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] aad) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(128, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("decrypt failed", e);
        }
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("hmac failed", e);
        }
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("sha-256 failed", e);
        }
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) return false;
        int difference = 0;
        for (int i = 0; i < a.length; i++) difference |= a[i] ^ b[i];
        return difference == 0;
    }

    private static byte[] hexDecode(String value) {
        int length = value.length();
        byte[] out = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            out[i / 2] = (byte) ((hexDigit(value.charAt(i)) << 4) | hexDigit(value.charAt(i + 1)));
        }
        return out;
    }

    private static int hexDigit(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        throw new IllegalArgumentException("bad hex digit: " + c);
    }

    private static String hex(byte[] data) {
        char[] out = new char[data.length * 2];
        for (int i = 0; i < data.length; i++) {
            int value = data[i] & 0xff;
            out[i * 2] = HEX_DIGITS[value >>> 4];
            out[i * 2 + 1] = HEX_DIGITS[value & 0x0f];
        }
        return new String(out);
    }

    // ------------------------------------------------------------------ resource helpers

    private static byte[] readResource(String name) {
        try (InputStream in = ChimeraRuntime.class.getResourceAsStream(name)) {
            return in == null ? null : readAll(in);
        } catch (IOException e) {
            throw new IllegalStateException("resource read failed: " + name, e);
        }
    }

    private static byte[] readClasspathResource(ClassLoader loader, String name) {
        // ClassLoader.getResourceAsStream does not accept a leading '/'; only Class.getResource
        // does. Strip it so both the manifest lookup and the runtime stay correct.
        String resourceName = name.startsWith("/") ? name.substring(1) : name;
        try (InputStream in = loader.getResourceAsStream(resourceName)) {
            return in == null ? null : readAll(in);
        } catch (IOException e) {
            throw new IllegalStateException("resource read failed: " + name, e);
        }
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        int read;
        while ((read = in.read(chunk)) > 0) out.write(chunk, 0, read);
        return out.toByteArray();
    }

    private static String normalizeResourcePath(String resource) {
        return resource.startsWith("/") ? resource : "/" + resource;
    }

    private static String trimCarriageReturn(String line) {
        if (!line.isEmpty() && line.charAt(line.length() - 1) == '\r') {
            return line.substring(0, line.length() - 1);
        }
        return line;
    }

    // ------------------------------------------------------------------ binary block helpers

    private static byte[] readNonce(DataInputStream in) throws IOException {
        int length = in.readInt();
        if (length != NONCE_LENGTH) throw new IllegalStateException("bad nonce length: " + length);
        byte[] nonce = new byte[length];
        in.readFully(nonce);
        return nonce;
    }

    private static byte[] readBlock(DataInputStream in, int minLength) throws IOException {
        int length = in.readInt();
        if (length < minLength || length > MAX_BLOCK_LENGTH) {
            throw new IllegalStateException("bad block length: " + length);
        }
        byte[] data = new byte[length];
        in.readFully(data);
        return data;
    }

    // ------------------------------------------------------------------ module 4: license handshake

    /**
     * Performs the activation handshake with the license server:
     * X25519 ephemeral key pair -> POST /api/v1/license/activate -> verify the Ed25519 signature
     * over the canonical response -> ECDH + HKDF + AES-GCM unwrap of the content key ->
     * {@link #setContentKey(byte[])} + {@link #updateServerNonce(byte[])} -> start heartbeats.
     *
     * <p>Never throws to game code: any failure poisons the runtime and returns false.</p>
     */
    public static boolean authenticate(String account, String password, String hwid) {
        try {
            verifyRuntimeHash();
            if (poisoned) {
                return false;
            }
            if (!loadAuthConfig() || account == null || password == null || hwid == null) {
                markPoison();
                return false;
            }
            byte[] serverPublicRaw = Base64.getDecoder().decode(authServerPubkey);
            nativeSetAuthContext(serverPublicRaw, account.getBytes(StandardCharsets.UTF_8));
            byte[] clientPublic = nativeCreateClientKey();
            if (clientPublic == null || clientPublic.length != 32) {
                markPoison();
                return false;
            }
            String request = "{\"account\":" + jsonQuote(account)
                    + ",\"password\":" + jsonQuote(password)
                    + ",\"hwid\":" + jsonQuote(hwid)
                    + ",\"client_ephemeral_pub\":\""
                    + Base64.getEncoder().encodeToString(clientPublic) + "\"}";
            Object[] response = httpPost("/api/v1/license/activate", request);
            if (response == null || ((Integer) response[0]).intValue() != 200) {
                markPoison();
                return false;
            }
            String responseBody = (String) response[1];
            Map<String, String> fields = parseFlatJson(responseBody);
            String nonceText = fields.get("server_nonce");
            String expiresText = fields.get("expires_at");
            String token = fields.get("token");
            String sequenceText = fields.get("sequence");
            String issuedText = fields.get("issued_at");
            if (nonceText == null || expiresText == null || token == null
                    || sequenceText == null || issuedText == null) {
                markPoison();
                return false;
            }
            long expires = Long.parseLong(expiresText.trim());
            long sequence = Long.parseLong(sequenceText.trim());
            long issuedAt = Long.parseLong(issuedText.trim());
            byte[] nonce = Base64.getDecoder().decode(nonceText);
            if (nonce.length != AUTH_NONCE_LENGTH) {
                markPoison();
                return false;
            }
            // B1: nativeVerifyAuth returns a SessionHandle, never key bytes. Every path returns the
            // same long shape; a canary operation (not the auth return value) decides success, so
            // a 32-byte poison key can no longer be mistaken for a valid key.
            long handle = nativeVerifyAuth(responseBody.getBytes(StandardCharsets.UTF_8),
                    hwid.getBytes(StandardCharsets.UTF_8));
            if (handle == 0L) {
                markPoison();
                return false;
            }
            nativeCheckHandle(handle); // shape-only query; never used as a success oracle
            byte[] canary = nativeCompute(handle, new byte[]{NATIVE_OP_CANARY});
            if (canary == null || canary.length != 8 || bytesToLong(canary, 0) != 1L) {
                // B7 op10: release 下 nativeVerifyAuth 严格返回 PENDING；由 native 内部
                // RUN_DECISION_PROGRAM 完成 CALL_NATIVE→tag→VERIFY_DECISION 后 canary 才为 1。
                // 不是 Java 假接线：transcript/sig/判定主体全部留在 C++。
                ChimeraVmRuntime.runDecisionProgram(handle);
                canary = nativeCompute(handle, new byte[]{NATIVE_OP_CANARY});
            }
            if (canary == null || canary.length != 8 || bytesToLong(canary, 0) != 1L) {
                nativeSessionHandle = 0L;
                markPoison();
                return false;
            }
            if (sequence < 1 || !clockAcceptable(issuedAt)) {
                nativeSessionHandle = 0L;
                markPoison();
                return false;
            }
            // B7-pre/KI-26: remember the activation credentials for the handle-expiry retry path.
            authCachedAccount = account;
            authCachedPassword = password;
            authCachedHwid = hwid;
            installNativeHandle(handle);
            updateServerNonce(nonce);
            authToken = token;
            authExpiresAt = expires;
            authLastSequence = sequence;
            authLastIssuedAt = issuedAt;
            authHeartbeatFailures = 0;
            startHeartbeat();
            return true;
        } catch (Throwable t) {
            markPoison();
            return false;
        }
    }

    /**
     * Injected-prologue entry point (M7) with no annotation values: reads the system properties
     * {@code chimera.account}, {@code chimera.password} and {@code chimera.hwid}. No string
     * constants are injected, so the check works before any content key is available.
     */
    public static boolean preGameCheckFromProperties() {
        return preGameCheck(System.getProperty("chimera.account", ""),
                System.getProperty("chimera.password", ""),
                System.getProperty("chimera.hwid", ""));
    }

    /**
     * Injected-prologue entry point (M7): empty annotation values fall back to the system
     * properties {@code chimera.account}, {@code chimera.password} and {@code chimera.hwid}.
     * Never throws; returns false when the runtime is poisoned or activation fails.
     */
    public static boolean preGameCheckWithFallback(String account, String password, String hwid) {
        String resolvedAccount = account == null || account.isEmpty()
                ? System.getProperty("chimera.account", "") : account;
        String resolvedPassword = password == null || password.isEmpty()
                ? System.getProperty("chimera.password", "") : password;
        String resolvedHwid = hwid == null || hwid.isEmpty()
                ? System.getProperty("chimera.hwid", "") : hwid;
        return preGameCheck(resolvedAccount, resolvedPassword, resolvedHwid);
    }

    /**
     * Module 4 entry point: run all pre-game checks (runtime integrity, agent/anti-debug signals,
     * native activation) before the player joins a world. Never throws; on failure the runtime is
     * poisoned and business values degrade silently (negative ints / NaN doubles).
     */
    public static boolean preGameCheck(String account, String password, String hwid) {
        try {
            verifyRuntimeHash();
            ensureAgentSignals();
            if (poisoned || timingAgentDetected) {
                markPoison();
                return false;
            }
            return authenticate(account, password, hwid);
        } catch (Throwable t) {
            markPoison();
            return false;
        }
    }

    /**
     * One heartbeat round-trip. On success the server nonce is rotated and all session stamps are
     * invalidated (dynamic masks change); failure returns false and leaves the session usable so
     * the background thread can retry.
     */
    public static boolean heartbeatNow() {
        try {
            String token = authToken;
            if (token == null || !loadAuthConfig()) {
                return false;
            }
            // B7-pre/KI-26: renew a handle that expired while idle before touching the token, so the
            // heartbeat uses the freshly activated token instead of the stale one.
            if (nativeSessionHandle != 0L && !ensureSessionHealthy()) {
                return false;
            }
            token = authToken;
            if (token == null) {
                return false;
            }
            Object[] response = httpPost("/api/v1/license/heartbeat",
                    "{\"token\":" + jsonQuote(token) + "}");
            if (response == null || ((Integer) response[0]).intValue() != 200) {
                return false;
            }
            String responseBody = (String) response[1];
            Map<String, String> fields = parseFlatJson(responseBody);
            String nonceText = fields.get("server_nonce");
            String expiresText = fields.get("expires_at");
            String signatureText = fields.get("signature");
            String sequenceText = fields.get("sequence");
            String issuedText = fields.get("issued_at");
            if (nonceText == null || expiresText == null || signatureText == null
                    || sequenceText == null || issuedText == null) {
                return false;
            }
            long expires = Long.parseLong(expiresText.trim());
            long sequence = Long.parseLong(sequenceText.trim());
            long issuedAt = Long.parseLong(issuedText.trim());
            // Native Ed25519 verification (the Java layer never runs asymmetric crypto).
            if (nativeVerifyHeartbeat(responseBody.getBytes(StandardCharsets.UTF_8),
                    token.getBytes(StandardCharsets.UTF_8)) != 1) {
                return false;
            }
            // Replay / rollback defence: an attacker who blocks the live response and injects an
            // older (but validly signed) heartbeat must poison the session, not silently succeed.
            if (sequence <= authLastSequence) {
                markPoison();
                return false;
            }
            if (!clockAcceptable(issuedAt) || issuedAt < authLastIssuedAt) {
                markPoison();
                return false;
            }
            byte[] nonce = Base64.getDecoder().decode(nonceText);
            if (nonce.length != AUTH_NONCE_LENGTH) {
                return false;
            }
            updateServerNonce(nonce);
            authExpiresAt = expires;
            authLastSequence = sequence;
            authLastIssuedAt = issuedAt;
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    /** Background heartbeat loop; three consecutive failures poison the runtime. */
    @Override
    public void run() {
        while (true) {
            long interval = authHeartbeatMs;
            if (interval < 1000L) {
                interval = 1000L;
            }
            try {
                Thread.sleep(interval);
            } catch (InterruptedException e) {
                return;
            }
            if (authToken == null) {
                return;
            }
            if (heartbeatNow()) {
                authHeartbeatFailures = 0;
            } else {
                authHeartbeatFailures++;
                if (authHeartbeatFailures >= HEARTBEAT_FAILURES_BEFORE_POISON) {
                    markPoison();
                }
            }
        }
    }

    /**
     * Whether the dev/test system properties ({@code chimera.auth.*}) may influence this run.
     *
     * <p>SECURITY (2026-10-22): these are plain JVM properties, so a player could start the game
     * with {@code -Dchimera.auth.autoHeartbeat=false} and the background heartbeat thread would
     * never start — the client would validate once at launch and then keep running forever with
     * the server gone. The native release DLL is the anchor (VMP'd, cannot claim to be a dev
     * build), so a release artifact ignores the switches entirely.</p>
     */
    private static boolean devAuthSwitchesAllowed() {
        try {
            if (!isNativeLoaded()) {
                // No native module means no authentication at all (fail closed elsewhere);
                // keep dev iteration working in that state.
                return true;
            }
            return nativeDevBuild() != 0;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static void startHeartbeat() {
        if (devAuthSwitchesAllowed()
                && "false".equalsIgnoreCase(System.getProperty(AUTH_AUTO_HEARTBEAT_PROPERTY, "true"))) {
            return;
        }
        Thread existing = authHeartbeatThread;
        if (existing != null && existing.isAlive()) {
            return;
        }
        Thread thread = new Thread(AUTH_THREAD_BODY, "chimera-auth-heartbeat");
        thread.setDaemon(true);
        authHeartbeatThread = thread;
        thread.start();
    }

    /** Reads /chimera/auth.dat (system properties win); returns true when usable. */
    private static boolean loadAuthConfig() {
        // P2-1: a build-pinned server URL wins over both the system property and auth.dat. Without
        // this, editing one line of a plaintext jar resource repointed the client at another host.
        boolean pinnedServerUsed = false;
        String server = null;
        if (nativeAuthLoaded) {
            try {
                String pinned = nativePinnedAuthServer();
                if (pinned != null && !pinned.isBlank()) {
                    server = pinned;
                    pinnedServerUsed = true;
                }
            } catch (Throwable ignored) {
                // older DLL without the export: fall back to the file
            }
        }
        if (server == null) {
            server = System.getProperty(AUTH_SERVER_PROPERTY);
        }
        String pubkey = System.getProperty(AUTH_PUBKEY_PROPERTY);
        String pin = System.getProperty(AUTH_PIN_PROPERTY);
        String insecure = System.getProperty(AUTH_ALLOW_INSECURE_PROPERTY);
        String skew = System.getProperty(AUTH_CLOCK_SKEW_PROPERTY);
        if (server == null || pubkey == null) {
            try {
                byte[] data = readResource(AUTH_RESOURCE);
                if (data != null) {
                    String text = new String(data, StandardCharsets.UTF_8);
                    String[] lines = text.split("\n");
                    for (String rawLine : lines) {
                        String line = trimCarriageReturn(rawLine).trim();
                        if (line.isEmpty() || line.startsWith("#")) {
                            continue;
                        }
                        int equals = line.indexOf('=');
                        if (equals <= 0) {
                            continue;
                        }
                        String key = line.substring(0, equals).trim();
                        String value = line.substring(equals + 1).trim();
                        if ("server".equals(key) && server == null && !pinnedServerUsed) {
                            server = value;
                        } else if ("pubkey".equals(key) && pubkey == null) {
                            pubkey = value;
                        } else if ("heartbeatMs".equals(key)) {
                            try {
                                // Clamped: auth.dat is an editable jar resource with no integrity
                                // coverage, so an unbounded value would let an attacker stretch the
                                // heartbeat to effectively never (same effect as disabling it).
                                long parsed = Long.parseLong(value);
                                authHeartbeatMs = Math.min(MAX_HEARTBEAT_MS,
                                        Math.max(1000L, parsed));
                            } catch (NumberFormatException ignored) {
                                // keep the default
                            }
                        } else if ("pin".equals(key) && pin == null) {
                            pin = value;
                        } else if ("allowInsecure".equals(key) && insecure == null) {
                            insecure = value;
                        } else if ("clockSkewSeconds".equals(key) && skew == null) {
                            skew = value;
                        }
                    }
                }
            } catch (Throwable ignored) {
                // fall through: configuration is unavailable
            }
        }
        if (server == null || server.isBlank() || pubkey == null || pubkey.isBlank()) {
            return false;
        }
        if (server.endsWith("/")) {
            server = server.substring(0, server.length() - 1);
        }
        if (pin != null) {
            pin = pin.trim();
            if (pin.isEmpty()) {
                pin = null;
            }
        }
        authServer = server;
        authServerPubkey = pubkey;
        authServerPin = pin;
        authAllowInsecure = "true".equalsIgnoreCase(insecure);
        if (skew != null && !skew.isBlank()) {
            try {
                authClockSkewSeconds = Math.max(30L, Long.parseLong(skew.trim()));
            } catch (NumberFormatException ignored) {
                // keep the default
            }
        }
        return true;
    }

    private static long nowSeconds() {
        return System.currentTimeMillis() / 1000L;
    }

    private static boolean clockAcceptable(long issuedAt) {
        long delta = nowSeconds() - issuedAt;
        if (delta < 0) {
            delta = -delta;
        }
        return delta <= authClockSkewSeconds;
    }

    /** Returns {Integer status, String body} or null on transport failure. */
    private static Object[] httpPost(String path, String body) {
        try {
            URL url = new URL(authServer + path);
            String protocol = url.getProtocol();
            HttpURLConnection connection;
            if ("https".equalsIgnoreCase(protocol)) {
                HttpsURLConnection https = (HttpsURLConnection) url.openConnection();
                String pin = authServerPin;
                if (pin != null && !pin.isBlank()) {
                    ChimeraTlsPin.setPin(Base64.getDecoder().decode(pin));
                    ChimeraTlsPin.install(https);
                }
                connection = https;
            } else if ("http".equalsIgnoreCase(protocol)) {
                String host = url.getHost();
                boolean loopback = "127.0.0.1".equals(host) || "localhost".equals(host)
                        || "::1".equals(host) || "[::1]".equals(host);
                if (!authAllowInsecure && !loopback) {
                    return null;
                }
                connection = (HttpURLConnection) url.openConnection();
            } else {
                return null;
            }
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(15000);
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            connection.setRequestProperty("Accept", "application/json");
            byte[] payload = body.getBytes(StandardCharsets.UTF_8);
            connection.setFixedLengthStreamingMode(payload.length);
            try (java.io.OutputStream out = connection.getOutputStream()) {
                out.write(payload);
            }
            int status = connection.getResponseCode();
            InputStream input = status >= 400 ? connection.getErrorStream() : connection.getInputStream();
            String response = "";
            if (input != null) {
                try (InputStream stream = input) {
                    response = new String(readLimited(stream, 65536), StandardCharsets.UTF_8);
                }
            }
            connection.disconnect();
            return new Object[]{Integer.valueOf(status), response};
        } catch (Throwable t) {
            return null;
        }
    }

    private static byte[] readLimited(InputStream in, int limit) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(256);
        byte[] buffer = new byte[4096];
        int total = 0;
        int read;
        while ((read = in.read(buffer)) > 0) {
            if (total >= limit) {
                break;
            }
            int take = Math.min(read, limit - total);
            out.write(buffer, 0, take);
            total += take;
        }
        return out.toByteArray();
    }

    private static String jsonQuote(String value) {
        StringBuilder sb = new StringBuilder(value.length() + 2);
        sb.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
        return sb.toString();
    }

    /** Minimal flat-object JSON parser for the fixed license response shape. */
    private static Map<String, String> parseFlatJson(String json) {
        Map<String, String> values = new HashMap<>();
        if (json == null) {
            return values;
        }
        int index = 0;
        int length = json.length();
        while (index < length) {
            char c = json.charAt(index);
            if (c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == ',' || c == '{' || c == '}') {
                index++;
                continue;
            }
            if (c != '"') {
                index++;
                continue;
            }
            int[] position = new int[]{index + 1};
            String key = readJsonString(json, position);
            index = position[0];
            while (index < length && (json.charAt(index) == ' ' || json.charAt(index) == '\t'
                    || json.charAt(index) == ':')) {
                index++;
            }
            if (index >= length) {
                break;
            }
            String value;
            if (json.charAt(index) == '"') {
                position[0] = index + 1;
                value = readJsonString(json, position);
                index = position[0];
            } else {
                int start = index;
                while (index < length && json.charAt(index) != ',' && json.charAt(index) != '}') {
                    index++;
                }
                value = json.substring(start, index).trim();
            }
            if (key != null) {
                values.put(key, value);
            }
        }
        return values;
    }

    private static String readJsonString(String json, int[] position) {
        StringBuilder sb = new StringBuilder();
        int index = position[0];
        while (index < json.length()) {
            char c = json.charAt(index++);
            if (c == '"') {
                position[0] = index;
                return sb.toString();
            }
            if (c == '\\' && index < json.length()) {
                char escaped = json.charAt(index++);
                switch (escaped) {
                    case '"':
                        sb.append('"');
                        break;
                    case '\\':
                        sb.append('\\');
                        break;
                    case '/':
                        sb.append('/');
                        break;
                    case 'n':
                        sb.append('\n');
                        break;
                    case 'r':
                        sb.append('\r');
                        break;
                    case 't':
                        sb.append('\t');
                        break;
                    case 'u':
                        if (index + 4 <= json.length()) {
                            try {
                                sb.append((char) Integer.parseInt(json.substring(index, index + 4), 16));
                            } catch (NumberFormatException ignored) {
                                // keep the literal
                            }
                            index += 4;
                        }
                        break;
                    default:
                        sb.append(escaped);
                }
            } else {
                sb.append(c);
            }
        }
        position[0] = index;
        return sb.toString();
    }

}
