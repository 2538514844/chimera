// VMProtect SDK markers (release protection build only; dev DLLs never include them).
#if defined(CHIMERA_VMP_BUILD)
// The shipped SDK header only understands MSVC architecture macros; MinGW uses the same
// __stdcall DLL imports, declared directly here and linked against VMProtectSDK64.lib.
extern "C" __declspec(dllimport) void __stdcall VMProtectBeginVirtualization(const char*);
extern "C" __declspec(dllimport) void __stdcall VMProtectEnd(void);
// D: VMProtect's own image CRC. Declared at namespace scope - a linkage specification is not
// allowed inside a function body (GCC: "expected unqualified-id before string constant").
extern "C" __declspec(dllimport) int __stdcall VMProtectIsValidImageCRC(void);
#define CHIMERA_VMP_BEGIN(name) VMProtectBeginVirtualization(name)
#define CHIMERA_VMP_END() VMProtectEnd()
#else
#define CHIMERA_VMP_BEGIN(name)
#define CHIMERA_VMP_END()
#endif

// Chimera native auth (M8): Ed25519 verify + X25519 unwrap + AES-256-GCM + HKDF + anti-debug.
//
// Build (MinGW, OpenSSL statically linked):
//   chimera-obfuscator/scripts/build-native-auth.ps1
// which runs: g++ -shared -O2 -std=c++17 ... -static -static-libgcc -static-libstdc++
//             -lcrypto -lssl -lpsapi -lws2_32 -lcrypt32 -luser32 -ladvapi32 -lbcrypt -luserenv
// The result imports only Windows system DLLs: no libcrypto-3-x64.dll, no libssl, no
// libgcc/libstdc++/libwinpthread. Ship exactly one chimera_auth.dll.
//
// Black-box contract: every failure (bad signature, unwrap failure, debugger/agent detected)
// returns a formatted 32-byte POISON key. Never throws, never returns null/empty.

#include <jni.h>
#include <jvmti.h>
#include <mutex>
#include <windows.h>
#include <wincrypt.h>  // DPAPI: CryptProtectData / CryptUnprotectData (v4 client key at rest)
#include <bcrypt.h>    // CNG: keeps the class-body key out of user-mode memory (see g_class_key)
#if defined(__GNUC__)
#include <cpuid.h>     // __get_cpuid for the hypervisor vendor-string check
#endif
#include <psapi.h>
#include <tlhelp32.h>   // #DR: thread enumeration for hardware-breakpoint detection
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

CRITICAL_SECTION g_lock;
bool g_lock_ready = false;

unsigned char g_client_priv[32];
bool g_have_client_priv = false;
unsigned char g_server_pub[32];
bool g_have_server_pub = false;
unsigned char g_account[512];
size_t g_account_len = 0;

/**
 * Process-wide lock protecting the handle table and every mutable global below.
 *
 * <p>Red team round 4 (source audit): {@code ensure_lock()} used a plain {@code if (!ready)} test, so
 * two threads reaching the first JNI call together could both run {@code InitializeCriticalSection}
 * and leave one of them with a re-initialised lock. {@code LockGuard} then re-read {@code
 * g_lock_ready} on destruction, so a guard constructed before the flag was set would skip
 * {@code EnterCriticalSection} but still call {@code LeaveCriticalSection} - releasing a lock its
 * thread never held. Both are fixed: the section is initialised exactly once by the OS, and the
 * guard remembers whether it actually entered.</p>
 */
struct LockGuard {
    bool owned;

    LockGuard() : owned(g_lock_ready) {
        if (owned) EnterCriticalSection(&g_lock);
    }

    ~LockGuard() {
        if (owned) LeaveCriticalSection(&g_lock);
    }

    LockGuard(const LockGuard&) = delete;
    LockGuard& operator=(const LockGuard&) = delete;
};

void ensure_lock() {
    static INIT_ONCE once = INIT_ONCE_STATIC_INIT;
    InitOnceExecuteOnce(&once,
            [](PINIT_ONCE, PVOID, PVOID*) -> BOOL {
                InitializeCriticalSection(&g_lock);
                g_lock_ready = true;
                return TRUE;
            },
            nullptr, nullptr);
}

// ------------------------------------------------------------------ B7 fixed resources
//
// B7 step 2: every runtime path below uses these JNI_OnLoad-allocated objects and a fixed arena;
// no new/malloc/std::vector growth is allowed in the op6..op9 native paths. SecureZeroMemory wipes
// all intermediate key/plaintext buffers immediately (task seven / KI-03 hardening).

void secure_wipe(void* data, size_t size) {
    if (data != nullptr && size != 0) SecureZeroMemory(data, size);
}

constexpr size_t kVerifyCtxPoolSize = 4;
constexpr size_t kCipherCtxPoolSize = 4;
constexpr size_t kPkeyCtxPoolSize = 4;
constexpr size_t kArenaSize = 64 * 1024;

EVP_MD_CTX* g_verify_ctx_pool[kVerifyCtxPoolSize] = {};
volatile LONG g_verify_ctx_busy[kVerifyCtxPoolSize] = {};
// Second, independent EVP_MD_CTX pool for the B7-2 second verification path (same one-shot
// EVP_DigestVerify API; Ed25519 does not support EVP_PKEY_verify on OpenSSL).
EVP_MD_CTX* g_verify_independent_pool[kVerifyCtxPoolSize] = {};
volatile LONG g_verify_independent_busy[kVerifyCtxPoolSize] = {};
EVP_CIPHER_CTX* g_cipher_ctx_pool[kCipherCtxPoolSize] = {};
volatile LONG g_cipher_ctx_busy[kCipherCtxPoolSize] = {};
EVP_PKEY* g_pinned_ed_pub = nullptr;
EVP_PKEY_CTX* g_verify_pkey_ctx_pool[kPkeyCtxPoolSize] = {};
volatile LONG g_verify_pkey_ctx_busy[kPkeyCtxPoolSize] = {};
bool g_verify_ctx_pool_ready = false;
bool g_cipher_ctx_pool_ready = false;
bool g_pkey_ctx_pool_ready = false;

alignas(16) unsigned char g_arena[kArenaSize];
size_t g_arena_used = 0;

// B7-6: explicit window marker/counter for the "no heap" check. Frida can bracket the window via
// the dev exports below and count msvcrt!malloc externally; b7_heap_note() is the internal counter
// used by self-tests / any future allocation that must be zero inside the window.
volatile LONG g_heap_window_active = 0;
volatile LONG g_heap_window_allocs = 0;

// B6: JVMTI environment captured in JNI_OnLoad (GetEnv works for System.load'd libraries on
// JDK 21; no -agentpath required). can_get_bytecodes lets us hash the actual hidden-class bytes
// AFTER defineHiddenClass instead of trusting the Java-side input array.
jvmtiEnv* g_jvmti = nullptr;
bool g_jvmti_bytecodes = false;

void b7_heap_note() {
    if (InterlockedCompareExchange(&g_heap_window_active, 1, 1) == 1) {
        InterlockedIncrement(&g_heap_window_allocs);
    }
}

// CHIMERA_TEST_MODE: dev builds only, enabled by the CHIMERA_TEST_MODE/CHIMERA_ALLOW_FRIDA env var
// before JVM start. It bypasses B3-1 code-section self-checks and native anti-debug poisoning so a
// post-JNI_OnLoad Frida attach can be exercised; pool/concurrency and wall-clock defenses stay on.
bool g_test_mode = false;
bool g_force_verify_result_enabled = false;
int g_force_verify_result = 0;
unsigned char g_vm_session_nonce[32];
bool g_have_vm_session_nonce = false;

void arena_reset() {
    g_arena_used = 0;
}

void* arena_alloc(size_t size, size_t alignment) {
    if (size == 0 || alignment == 0) return nullptr;
    const size_t offset = (g_arena_used + alignment - 1) & ~(alignment - 1);
    if (offset > kArenaSize || size > kArenaSize - offset) return nullptr;
    g_arena_used = offset + size;
    return g_arena + offset;
}

void arena_wipe_and_reset() {
    if (g_arena_used != 0) secure_wipe(g_arena, g_arena_used);
    arena_reset();
}

bool acquire_verify_ctx(EVP_MD_CTX** out) {
    if (!g_verify_ctx_pool_ready) return false;
    for (size_t i = 0; i < kVerifyCtxPoolSize; i++) {
        if (InterlockedCompareExchange(&g_verify_ctx_busy[i], 1, 0) == 0) {
            *out = g_verify_ctx_pool[i];
            return *out != nullptr;
        }
    }
    return false;
}

void release_verify_ctx(EVP_MD_CTX* ctx) {
    for (size_t i = 0; i < kVerifyCtxPoolSize; i++) {
        if (g_verify_ctx_pool[i] == ctx) {
            EVP_MD_CTX_reset(ctx);
            InterlockedExchange(&g_verify_ctx_busy[i], 0);
            return;
        }
    }
}

bool acquire_independent_ctx(EVP_MD_CTX** out) {
    if (!g_verify_ctx_pool_ready) return false;
    for (size_t i = 0; i < kVerifyCtxPoolSize; i++) {
        if (InterlockedCompareExchange(&g_verify_independent_busy[i], 1, 0) == 0) {
            *out = g_verify_independent_pool[i];
            return *out != nullptr;
        }
    }
    return false;
}

void release_independent_ctx(EVP_MD_CTX* ctx) {
    for (size_t i = 0; i < kVerifyCtxPoolSize; i++) {
        if (g_verify_independent_pool[i] == ctx) {
            EVP_MD_CTX_reset(ctx);
            InterlockedExchange(&g_verify_independent_busy[i], 0);
            return;
        }
    }
}

bool acquire_cipher_ctx(EVP_CIPHER_CTX** out) {
    if (!g_cipher_ctx_pool_ready) return false;
    for (size_t i = 0; i < kCipherCtxPoolSize; i++) {
        if (InterlockedCompareExchange(&g_cipher_ctx_busy[i], 1, 0) == 0) {
            *out = g_cipher_ctx_pool[i];
            return *out != nullptr;
        }
    }
    return false;
}

void release_cipher_ctx(EVP_CIPHER_CTX* ctx) {
    for (size_t i = 0; i < kCipherCtxPoolSize; i++) {
        if (g_cipher_ctx_pool[i] == ctx) {
            EVP_CIPHER_CTX_reset(ctx);
            InterlockedExchange(&g_cipher_ctx_busy[i], 0);
            return;
        }
    }
}

bool acquire_pkey_ctx(EVP_PKEY_CTX** out) {
    if (!g_pkey_ctx_pool_ready) return false;
    for (size_t i = 0; i < kPkeyCtxPoolSize; i++) {
        if (InterlockedCompareExchange(&g_verify_pkey_ctx_busy[i], 1, 0) == 0) {
            *out = g_verify_pkey_ctx_pool[i];
            return *out != nullptr;
        }
    }
    return false;
}

void release_pkey_ctx(EVP_PKEY_CTX* ctx) {
    for (size_t i = 0; i < kPkeyCtxPoolSize; i++) {
        if (g_verify_pkey_ctx_pool[i] == ctx) {
            InterlockedExchange(&g_verify_pkey_ctx_busy[i], 0);
            return;
        }
    }
}

bool env_flag_enabled(const char* name) {
    const char* value = std::getenv(name);
    if (value == nullptr) return false;
    return value[0] == '1'
            || _stricmp(value, "true") == 0
            || _stricmp(value, "on") == 0
            || _stricmp(value, "yes") == 0;
}

// ------------------------------------------------------------------ base64

const char B64_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

bool b64_decode(const std::string& in, std::vector<unsigned char>& out) {
    out.clear();
    int val = 0;
    int bits = -8;
    for (unsigned char c : in) {
        if (c == '=') break;
        const char* pos = std::strchr(B64_CHARS, c);
        if (pos == nullptr || c == '\0') return false;
        val = (val << 6) + static_cast<int>(pos - B64_CHARS);
        bits += 6;
        if (bits >= 0) {
            out.push_back(static_cast<unsigned char>((val >> bits) & 0xff));
            bits -= 8;
        }
    }
    return true;
}

std::string b64_encode(const unsigned char* data, size_t len) {
    std::string out;
    int val = 0;
    int bits = -6;
    for (size_t i = 0; i < len; i++) {
        val = (val << 8) + data[i];
        bits += 8;
        while (bits >= 0) {
            out.push_back(B64_CHARS[(val >> bits) & 0x3f]);
            bits -= 6;
        }
    }
    if (bits > -6) out.push_back(B64_CHARS[((val << 8) >> (bits + 8)) & 0x3f]);
    while (out.size() % 4 != 0) out.push_back('=');
    return out;
}

// ------------------------------------------------------------------ minimal flat JSON

bool find_raw(const std::string& json, const std::string& key, std::string& value, bool quoted) {
    std::string needle = "\"" + key + "\"";
    size_t at = json.find(needle);
    if (at == std::string::npos) return false;
    size_t colon = json.find(':', at + needle.size());
    if (colon == std::string::npos) return false;
    size_t i = colon + 1;
    while (i < json.size() && (json[i] == ' ' || json[i] == '\t')) i++;
    if (i >= json.size()) return false;
    if (quoted) {
        if (json[i] != '"') return false;
        i++;
        value.clear();
        while (i < json.size() && json[i] != '"') {
            if (json[i] == '\\' && i + 1 < json.size()) {
                i++;
                value.push_back(json[i]);
            } else {
                value.push_back(json[i]);
            }
            i++;
        }
        return i < json.size();
    }
    size_t start = i;
    while (i < json.size() && json[i] != ',' && json[i] != '}') i++;
    value = json.substr(start, i - start);
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.pop_back();
    return !value.empty();
}

bool find_string(const std::string& json, const std::string& key, std::string& value) {
    return find_raw(json, key, value, true);
}

bool find_long(const std::string& json, const std::string& key, long long& value) {
    std::string raw;
    if (!find_raw(json, key, raw, false)) return false;
    char* end = nullptr;
    value = std::strtoll(raw.c_str(), &end, 10);
    return end != raw.c_str();
}

// -------------------------------------------------------------- anti-debug (telemetry first)
//
// M7 anti-false-positive policy:
//   * Frida modules are explicit instrumentation -> poison in telemetry AND strict mode.
//   * Debugger signals (IsDebuggerPresent / remote debugger / NtQueryInformationProcess) are
//     telemetry-only by default. Strict mode must be opted into
//     (-Dchimera.native.antidebug=strict) and even then a loaded security product
//     (Defender/AV/EDR modules) downgrades the decision to telemetry, because their user-mode
//     hooks can make IsDebuggerPresent return a false positive.
//   * off disables all native anti-debug decisions.

bool contains_ci(const char* haystack, const char* needle) {
    if (!haystack || !needle) return false;
    std::string h(haystack);
    std::string n(needle);
    for (char& c : h) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
    return h.find(n) != std::string::npos;
}

enum AntiDebugMode {
    kAntiDebugTelemetry = 0,
    kAntiDebugStrict = 1,
    kAntiDebugOff = 2
};

enum DetectionFlags {
    kDetectNone = 0,
    kDetectDebugger = 1,
    kDetectFrida = 2
};

volatile LONG g_anti_debug_mode = kAntiDebugTelemetry;
volatile LONG g_anti_debug_signals = 0;
volatile LONG g_anti_debug_telemetry_logs = 0;

bool is_security_software(const char* module_name) {
    static const char* const kModules[] = {
            "msmpeng", "mpdefender", "mpclient", "avastui", "avastsvc", "avira", "avgui",
            "avgtray", "eset", "ekrn", "egui", "kaspersky", "avpui", "klif", "bitdefender",
            "bdagent", "crowdstrike", "csagent", "csfalcon", "sentinelone", "sentinelagent",
            "sentinelmemoryscanner", "carbonblack", "symantec", "ccsvchst", "mcafee",
            "mcshield", "trendmicro", "tmnt", "sophos", "savservice", "360tray", "360safe",
            "huorong", "hipsdaemon", "qqpcmgr", "kingsoft", "kxe", "qqprotect", "hisec"
    };
    for (const char* marker : kModules) {
        if (contains_ci(module_name, marker)) return true;
    }
    return false;
}

struct Detection {
    DWORD flags;
    bool security_software;
};

Detection detect_instrumentation() {
    Detection result{kDetectNone, false};

    HMODULE modules[1024];
    DWORD needed = 0;
    if (EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &needed)) {
        const DWORD count = needed / sizeof(HMODULE);
        char name[MAX_PATH];
        for (DWORD i = 0; i < count; i++) {
            if (GetModuleBaseNameA(GetCurrentProcess(), modules[i], name, MAX_PATH) > 0) {
                if (contains_ci(name, "frida")) result.flags |= kDetectFrida;
                if (is_security_software(name)) result.security_software = true;
            }
        }
    }

    if (IsDebuggerPresent()) result.flags |= kDetectDebugger;
    BOOL remote = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote) {
        result.flags |= kDetectDebugger;
    }

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll != nullptr) {
        typedef LONG(NTAPI* NtQueryInformationProcessFn)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        auto query = reinterpret_cast<NtQueryInformationProcessFn>(
                GetProcAddress(ntdll, "NtQueryInformationProcess"));
        if (query != nullptr) {
            DWORD_PTR debugPort = 0;
            ULONG returned = 0;
            if (query(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), &returned) == 0
                    && debugPort != 0) {
                result.flags |= kDetectDebugger;
            }
            DWORD debugFlags = 0;
            if (query(GetCurrentProcess(), 31, &debugFlags, sizeof(debugFlags), &returned) == 0
                    && debugFlags == 0) {
                result.flags |= kDetectDebugger;
            }
        }
    }
    return result;
}

void anti_debug_telemetry(const Detection& detection, LONG mode, const char* decision) {
    LONG count = InterlockedIncrement(&g_anti_debug_telemetry_logs);
    if (count > 20 && count % 100 != 0) return;
    std::fprintf(stderr,
                 "[chimera-native] anti-debug flags=0x%lx security_software=%d mode=%ld decision=%s\n",
                 static_cast<unsigned long>(detection.flags),
                 detection.security_software ? 1 : 0,
                 static_cast<long>(mode), decision);
    std::fflush(stderr);
}

bool should_poison() {
    if (g_test_mode) return false;  // CHIMERA_TEST_MODE: allow post-load instrumentation
    LONG mode = g_anti_debug_mode;
#if defined(CHIMERA_DEV_BUILD)
    if (mode == kAntiDebugOff) return false;
#else
    // Phase 0 (C-02): release DLLs ignore the "off" downgrade even if a caller forced it.
    if (mode == kAntiDebugOff) mode = kAntiDebugTelemetry;
#endif

    Detection detection = detect_instrumentation();
    if (detection.flags == kDetectNone) return false;

    InterlockedIncrement(&g_anti_debug_signals);
    if ((detection.flags & kDetectFrida) != 0) {
        anti_debug_telemetry(detection, mode, "poison: frida module");
        return true;
    }
    // Debugger signal only: never punish a paying player by default.
    bool poison = (mode == kAntiDebugStrict) && !detection.security_software;
    anti_debug_telemetry(detection, mode,
                         poison ? "poison: strict debugger" :
                         (detection.security_software ? "telemetry: security software whitelist"
                                                      : "telemetry: debugger signal"));
    return poison;
}

// ------------------------------------------------------------------ poison

std::vector<unsigned char> poison_key(const unsigned char* hwid, size_t hwid_len) {
    unsigned char seed[64 + 32];
    size_t n = 0;
    const char* tag = "chimera-native-poison-v1";
    std::memcpy(seed, tag, std::strlen(tag));
    n = std::strlen(tag);
    size_t take = hwid_len > 32 ? 32 : hwid_len;
    std::memcpy(seed + n, hwid, take);
    n += take;
    DWORD tick = GetTickCount();
    std::memcpy(seed + n, &tick, sizeof(tick));
    n += sizeof(tick);
    unsigned char digest[32];
    SHA256(seed, n, digest);
    for (int i = 0; i < 32; i++) digest[i] ^= 0xA5;
    return std::vector<unsigned char>(digest, digest + 32);
}

// ------------------------------------------------------------------ SessionHandle table
//
// A1/B1: nativeVerifyAuth returns a 64-bit handle, never key bytes. The product content key
// stays in this table. All return paths (success / signature failure / debugger / poison) return
// a random-looking nonzero long with the same shape. nativeCheckHandle/nativeCompute operate on
// the handle; Java never receives the 32-byte product key.

constexpr size_t kMaxHandles = 64;

// B7-pre/KI-26: sliding idle TTL, bounded to the 5-15 minute spec window. A handle is only lost
// through expiry, explicit revoke, or LRU eviction from a full table — never a blind ring
// overwrite.
constexpr uint64_t kHandleTtlDefaultMs = 10ULL * 60ULL * 1000ULL;
#if defined(CHIMERA_DEV_BUILD)
// Dev/test build only: allow a short TTL so the real-wait expiry test elapses in seconds.
constexpr uint64_t kHandleTtlMinMs = 1ULL * 1000ULL;
#else
constexpr uint64_t kHandleTtlMinMs = 5ULL * 60ULL * 1000ULL;
#endif
constexpr uint64_t kHandleTtlMaxMs = 15ULL * 60ULL * 1000ULL;

enum HandleState : uint32_t {
    kHandleFree = 0,
    kHandleValid = 1,
    kHandlePoison = 2,
    kHandlePending = 3
};

struct HandleSlot {
    uint64_t handle;
    unsigned char key[32];
    unsigned char transcript[1024];
    uint16_t transcript_len;
    unsigned char signature[64];
    // KI-28: per-(account,hwid) resource key; never JNI-exposed. Red team round 5: stored SEALED
    // under a per-process KEK (see unseal_slot_key) instead of in the clear, so a memory scan of
    // the DLL's data section finds noise rather than a 32-byte master key. The plaintext only
    // exists on the stack for the duration of one crypto call.
    unsigned char sealed_key[32];
    unsigned char nonce[16];
    uint32_t state;
    uint32_t verify_result;
    uint32_t resource_key_set;
    uint64_t created;
    uint64_t last_used;
};

HandleSlot g_handles[kMaxHandles];
uint64_t g_handle_ttl_ms = kHandleTtlDefaultMs;

void wipe_slot_locked(HandleSlot& slot) {
    secure_wipe(&slot, sizeof(slot));
    slot.state = kHandleFree;
}

bool slot_expired_locked(const HandleSlot& slot, uint64_t now) {
    return slot.state != kHandleFree && now > slot.last_used
            && now - slot.last_used > g_handle_ttl_ms;
}

uint64_t random_u64() {
    unsigned char bytes[8];
    if (RAND_bytes(bytes, sizeof(bytes)) != 1) {
        uint64_t fallback = GetTickCount64() ^ (static_cast<uint64_t>(GetCurrentThreadId()) << 32);
        return fallback == 0 ? 1 : fallback;
    }
    uint64_t value = 0;
    std::memcpy(&value, bytes, sizeof(value));
    // Nonzero and same shape for every path; do not encode success/failure in the value.
    value &= 0x7fffffffffffffffULL;
    return value == 0 ? 1 : value;
}

void reap_expired_locked(uint64_t now) {
    for (size_t i = 0; i < kMaxHandles; i++) {
        if (slot_expired_locked(g_handles[i], now)) wipe_slot_locked(g_handles[i]);
    }
}

HandleSlot* store_handle_slot_locked(const unsigned char* key, const unsigned char* nonce,
                                     uint32_t state) {
    uint64_t now = GetTickCount64();
    reap_expired_locked(now);
    HandleSlot* victim = nullptr;
    for (size_t i = 0; i < kMaxHandles; i++) {
        if (g_handles[i].state == kHandleFree) {
            victim = &g_handles[i];
            break;
        }
    }
    if (victim == nullptr) {
        // KI-26: full table -> evict the least recently used slot (ties: oldest creation).
        victim = &g_handles[0];
        for (size_t i = 1; i < kMaxHandles; i++) {
            if (g_handles[i].last_used < victim->last_used
                    || (g_handles[i].last_used == victim->last_used
                        && g_handles[i].created < victim->created)) {
                victim = &g_handles[i];
            }
        }
    }
    wipe_slot_locked(*victim);
    victim->handle = random_u64();
    if (key != nullptr) std::memcpy(victim->key, key, 32);
    if (nonce != nullptr) std::memcpy(victim->nonce, nonce, 16);
    victim->state = state;
    victim->verify_result = 0;
    victim->resource_key_set = 0;
    victim->transcript_len = 0;
    victim->created = now;
    victim->last_used = now;
    return victim;
}

uint64_t store_handle_locked(const unsigned char* key, const unsigned char* nonce, uint32_t state) {
    return store_handle_slot_locked(key, nonce, state)->handle;
}

HandleSlot* find_handle_locked(uint64_t handle) {
    if (handle == 0) return nullptr;
    uint64_t now = GetTickCount64();
    for (size_t i = 0; i < kMaxHandles; i++) {
        HandleSlot& slot = g_handles[i];
        if (slot.state == kHandleFree || slot.handle != handle) continue;
        if (slot_expired_locked(slot, now)) {
            // Expired: wipe the key material while the slot still identifies this handle.
            wipe_slot_locked(slot);
            return nullptr;
        }
        slot.last_used = now;
        return &slot;
    }
    return nullptr;
}

jlong auth_poison_result(const std::vector<unsigned char>& hwid) {
    std::vector<unsigned char> poison = poison_key(hwid.data(), hwid.size());
    return static_cast<jlong>(store_handle_locked(poison.data(), nullptr, kHandlePoison));
}

std::vector<unsigned char> poison_bytes(uint64_t handle, size_t length) {
    unsigned char seed[16];
    std::memcpy(seed, &handle, sizeof(handle));
    uint64_t tick = GetTickCount64();
    std::memcpy(seed + sizeof(handle), &tick, sizeof(tick));
    unsigned char digest[32];
    SHA256(seed, sizeof(seed), digest);
    std::vector<unsigned char> out(length, 0);
    for (size_t i = 0; i < length; i++) out[i] = digest[i % 32];
    return out;
}

// ------------------------------------------------------------------ HKDF-SHA256

bool hkdf_sha256(const unsigned char* ikm, size_t ikm_len,
                 const unsigned char* salt, size_t salt_len,
                 const unsigned char* info, size_t info_len,
                 unsigned char* out, size_t out_len) {
    unsigned char prk[32];
    unsigned int prk_len = 0;
    if (HMAC(EVP_sha256(), salt, static_cast<int>(salt_len), ikm, ikm_len, prk, &prk_len) == nullptr
            || prk_len != 32) {
        return false;
    }
    unsigned char previous[32];
    size_t previous_len = 0;
    size_t offset = 0;
    unsigned char counter = 1;
    while (offset < out_len) {
        std::vector<unsigned char> block;
        block.insert(block.end(), previous, previous + previous_len);
        block.insert(block.end(), info, info + info_len);
        block.push_back(counter);
        unsigned int block_len = 0;
        if (HMAC(EVP_sha256(), prk, 32, block.data(), block.size(), previous, &block_len) == nullptr
                || block_len != 32) {
            return false;
        }
        previous_len = block_len;
        size_t take = out_len - offset;
        if (take > 32) take = 32;
        std::memcpy(out + offset, previous, take);
        offset += take;
        counter++;
    }
    return true;
}

// ------------------------------------------------------------------ sealed slot keys
//
// Red team round 5: the ResourceKey used to sit in HandleSlot as 32 plaintext bytes, and there are
// up to 64 slots - so a memory scanner found the master key in the DLL's BSS without any effort.
// It is now stored XOR-sealed under a per-process KEK, with a PER-SLOT keystream (otherwise all 64
// ciphertexts would be identical, which is its own signature), and the keystream is recomputed on
// every use rather than cached (a cached table is exactly what a scanner would XOR back with).
//
// This is friction, not cryptography: the KEK lives in the same process. Someone who can hook
// unseal_slot_key still gets the key. What it removes is "scan the data section once and you are
// done".

static unsigned char g_seal_kek[32];
static bool g_seal_kek_ready = false;

/** Generates the process KEK once. Called from JNI_OnLoad; fails closed if RNG is unavailable. */
void init_seal_kek() {
    if (g_seal_kek_ready) return;
    if (RAND_bytes(g_seal_kek, sizeof(g_seal_kek)) != 1) return;
    g_seal_kek_ready = true;
}

/** Slot index within the handle table; the seal label must not depend on the (random) handle. */
static size_t slot_index_of(const HandleSlot& slot) {
    const HandleSlot* base = &g_handles[0];
    const HandleSlot* p = &slot;
    if (p < base || p >= base + kMaxHandles) return kMaxHandles;
    return static_cast<size_t>(p - base);
}

/** Per-slot keystream. Label is the slot index, which is stable for the table's whole life. */
static bool slot_seal_stream(const HandleSlot& slot, unsigned char out[32]) {
    if (!g_seal_kek_ready) return false;
    const size_t index = slot_index_of(slot);
    if (index >= kMaxHandles) return false;
    char info[24];
    const int n = std::snprintf(info, sizeof(info), "slot-%zu", index);
    if (n <= 0 || static_cast<size_t>(n) >= sizeof(info)) return false;
    return hkdf_sha256(g_seal_kek, sizeof(g_seal_kek),
            reinterpret_cast<const unsigned char*>("chimera-slot-seal-v1"), 22,
            reinterpret_cast<const unsigned char*>(info), static_cast<size_t>(n), out, 32);
}

/** Seals {@code key} into the slot. Must run after the slot's handle has been assigned. */
static bool seal_slot_key(HandleSlot& slot, const unsigned char key[32]) {
    unsigned char ks[32];
    if (!slot_seal_stream(slot, ks)) return false;
    for (size_t i = 0; i < 32; i++) slot.sealed_key[i] = key[i] ^ ks[i];
    secure_wipe(ks, sizeof(ks));
    return true;
}

/** Unseals into a caller-provided stack buffer. The caller must wipe it. */
static bool unseal_slot_key(const HandleSlot& slot, unsigned char out[32]) {
    if (slot.resource_key_set == 0) return false;
    unsigned char ks[32];
    if (!slot_seal_stream(slot, ks)) return false;
    for (size_t i = 0; i < 32; i++) out[i] = slot.sealed_key[i] ^ ks[i];
    secure_wipe(ks, sizeof(ks));
    return true;
}

/**
 * RAII view of a slot's ResourceKey: unseals on construction, wipes on destruction.
 *
 * <p>Use this at every read site instead of touching {@code sealed_key} directly, so the plaintext
 * cannot outlive the call by accident. Falls back to the legacy {@code slot.key} for handles that
 * predate KI-28 (dev artifacts and pre-upgrade sessions).</p>
 */
struct SlotKey {
    unsigned char bytes[32];
    bool ok;

    explicit SlotKey(const HandleSlot& slot) : ok(false) {
        std::memset(bytes, 0, sizeof(bytes));
        if (slot.resource_key_set != 0) {
            ok = unseal_slot_key(slot, bytes);
        } else {
            std::memcpy(bytes, slot.key, sizeof(bytes));
            ok = true;
        }
    }

    ~SlotKey() {
        secure_wipe(bytes, sizeof(bytes));
    }

    const unsigned char* data() const {
        return bytes;
    }

    SlotKey(const SlotKey&) = delete;
    SlotKey& operator=(const SlotKey&) = delete;
};

// ------------------------------------------------------------------ CNG class-body key
//
// Red team round 5, layer 2: the class-body key is the same for every class (HKDF of the
// ResourceKey), so it used to be re-derived and materialised on the stack on every one of the 1156
// decryptions - a scanner only had to catch one of them, and the key unlocks every class anyway.
//
// It is now derived once, handed to CNG (BCryptGenerateSymmetricKey), and the plaintext is wiped.
// All class-body decryption goes through BCryptDecrypt with the handle, so the key material lives
// in the CNG provider rather than in this process's writable memory. This is the only place where
// that is worth the complexity: 1156 uses of one long-lived secret.
//
// Everything else (strings, indy, payload) still derives short-lived keys on demand, because they
// are used a handful of times and the CNG plumbing would not pay for itself.

static BCRYPT_ALG_HANDLE g_aes_alg = nullptr;
static BCRYPT_KEY_HANDLE g_class_key = nullptr;
static bool g_class_key_ready = false;

/** Drops the CNG handle. Called before re-installing and whenever the key changes. */
static void release_class_key() {
    if (g_class_key != nullptr) {
        BCryptDestroyKey(g_class_key);
        g_class_key = nullptr;
    }
    g_class_key_ready = false;
}

/**
 * Derives the class-body key from the slot's ResourceKey and hands it to CNG.
 *
 * <p>The plaintext exists only inside this function: it is derived into a stack buffer, imported,
 * and wiped. After that the only reference is an opaque handle.</p>
 */
static bool install_class_key(const HandleSlot& slot) {
    SlotKey resource_key(slot);
    if (!resource_key.ok) return false;

    unsigned char class_key[32];
    const unsigned char salt[] = "chimera-classenc-v1";
    const unsigned char info[] = "class-key";
    const bool derived = hkdf_sha256(resource_key.data(), 32, salt, sizeof(salt) - 1,
            info, sizeof(info) - 1, class_key, sizeof(class_key));
    if (!derived) {
        secure_wipe(class_key, sizeof(class_key));
        return false;
    }

    release_class_key();
    if (g_aes_alg == nullptr) {
        if (BCryptOpenAlgorithmProvider(&g_aes_alg, BCRYPT_AES_ALGORITHM, nullptr, 0) < 0) {
            g_aes_alg = nullptr;
            secure_wipe(class_key, sizeof(class_key));
            return false;
        }
        if (BCryptSetProperty(g_aes_alg, BCRYPT_CHAINING_MODE,
                reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                sizeof(BCRYPT_CHAIN_MODE_GCM), 0) < 0) {
            secure_wipe(class_key, sizeof(class_key));
            return false;
        }
    }
    if (BCryptGenerateSymmetricKey(g_aes_alg, &g_class_key, nullptr, 0,
            class_key, sizeof(class_key), 0) < 0) {
        g_class_key = nullptr;
        secure_wipe(class_key, sizeof(class_key));
        return false;
    }
    secure_wipe(class_key, sizeof(class_key));
    g_class_key_ready = true;
    return true;
}

/** AES-256-GCM decryption through the CNG handle. Writes exactly ct_len bytes into {@code out}. */
static bool bcrypt_gcm_decrypt(const unsigned char* nonce, size_t nonce_len,
                               const unsigned char* ct, size_t ct_len,
                               const unsigned char* tag, size_t tag_len,
                               const unsigned char* aad, size_t aad_len,
                               unsigned char* out, size_t* out_len) {
    if (!g_class_key_ready || g_class_key == nullptr) return false;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<PUCHAR>(nonce);
    info.cbNonce = static_cast<ULONG>(nonce_len);
    info.pbAuthData = const_cast<PUCHAR>(aad);
    info.cbAuthData = static_cast<ULONG>(aad_len);
    info.pbTag = const_cast<PUCHAR>(tag);
    info.cbTag = static_cast<ULONG>(tag_len);
    ULONG produced = 0;
    const NTSTATUS status = BCryptDecrypt(g_class_key, const_cast<PUCHAR>(ct),
            static_cast<ULONG>(ct_len), &info, nullptr, 0, out,
            static_cast<ULONG>(*out_len), &produced, 0);
    if (status < 0) return false;
    *out_len = produced;
    return true;
}

// ------------------------------------------------------------------ crypto helpers

bool ed25519_verify(const unsigned char* pub, const unsigned char* msg, size_t msg_len,
                    const unsigned char* sig, size_t sig_len) {
    if (sig_len != 64) return false;
    EVP_MD_CTX* pooled = nullptr;
    EVP_PKEY* key = nullptr;
    EVP_MD_CTX* ctx = nullptr;
    if (g_pinned_ed_pub != nullptr && acquire_verify_ctx(&pooled)) {
        ctx = pooled;
        key = g_pinned_ed_pub;
    } else {
        // Pre-config fallback only (before nativeSetAuthContext / JNI_OnLoad pools exist).
        key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pub, 32);
        ctx = EVP_MD_CTX_new();
    }
    const bool ok = ctx != nullptr && key != nullptr
            && EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, key) == 1
            && EVP_DigestVerify(ctx, sig, sig_len, msg, msg_len) == 1;
    if (pooled != nullptr) {
        release_verify_ctx(pooled);
    } else {
        if (ctx != nullptr) EVP_MD_CTX_free(ctx);
        if (key != nullptr) EVP_PKEY_free(key);
    }
    return ok;
}

// B7-2: second, independent Ed25519 verification through EVP_PKEY_verify. A hook/patch on
// EVP_DigestVerify alone cannot promote a handle: this entry point must agree too.
// B7-2 Frida target: exported wrapper around the primary EVP_DigestVerify path. Hooking this
// symbol (or forcing its return to 1) changes only the primary path; the independent BN/SHA-512
// verifier in ed25519_verify_bn still rejects forged signatures.
extern "C" __declspec(dllexport) __attribute__((noinline)) int chimera_b7_primary_verify(
        const unsigned char* pub, const unsigned char* msg, size_t msg_len,
        const unsigned char* sig, size_t sig_len) {
    return ed25519_verify(pub, msg, msg_len, sig, sig_len) ? 1 : 0;
}
// ------------------------------------------------------------------ independent Ed25519 verify
// B7-2 hard requirement: this path must NOT call EVP_DigestVerify / EVP_PKEY_verify. It decodes
// both Edwards points with BN field arithmetic, hashes R||A||M with low-level SHA-512, does
// scalar multiplication with a=-1 twisted Edwards addition, and compares [S]B with R+[k]A.
// A Frida hook on EVP_DigestVerify therefore cannot change this result.
struct EdwardsPoint {
    BIGNUM* x;
    BIGNUM* y;
};

void ed_point_free(EdwardsPoint& point) {
    BN_free(point.x);
    BN_free(point.y);
    point.x = nullptr;
    point.y = nullptr;
}

bool ed_decode_point(const unsigned char encoded[32], EdwardsPoint& out, const BIGNUM* p,
                     const BIGNUM* d, const BIGNUM* sqrt_m1, const BIGNUM* sqrt_exp, BN_CTX* ctx,
                     int* decode_stage = nullptr) {
    if (decode_stage != nullptr) *decode_stage = 0;
    unsigned char buffer[32];
    std::memcpy(buffer, encoded, 32);
    const int sign = buffer[31] >> 7;
    buffer[31] &= 0x7f;
    BN_CTX_start(ctx);
    BIGNUM* y = BN_CTX_get(ctx);
    BIGNUM* y2 = BN_CTX_get(ctx);
    BIGNUM* u = BN_CTX_get(ctx);
    BIGNUM* v = BN_CTX_get(ctx);
    BIGNUM* t = BN_CTX_get(ctx);
    BIGNUM* ratio = BN_CTX_get(ctx);
    BIGNUM* x = BN_CTX_get(ctx);
    bool ok = false;
    if (y != nullptr && y2 != nullptr && u != nullptr && v != nullptr && t != nullptr
            && ratio != nullptr && x != nullptr
            && BN_lebin2bn(buffer, 32, y) != nullptr && BN_cmp(y, p) < 0) {
        if (decode_stage != nullptr) *decode_stage = 1;
        BN_mod_mul(y2, y, y, p, ctx);
        BN_mod_sub(u, y2, BN_value_one(), p, ctx);
        BN_mod_mul(v, y2, d, p, ctx);
        BN_mod_add(v, v, BN_value_one(), p, ctx);
        if (decode_stage != nullptr) *decode_stage = 2;
        if (BN_mod_inverse(t, v, p, ctx) != nullptr) {
            if (decode_stage != nullptr) *decode_stage = 3;
            BN_mod_mul(ratio, u, t, p, ctx);
            BN_mod_exp(x, ratio, sqrt_exp, p, ctx);
            BN_mod_mul(t, x, x, p, ctx);
            BN_mod_mul(t, t, v, p, ctx);
            if (BN_cmp(t, u) != 0) {
                BN_mod_mul(x, x, sqrt_m1, p, ctx);
                BN_mod_mul(t, x, x, p, ctx);
                BN_mod_mul(t, t, v, p, ctx);
            }
            if (decode_stage != nullptr) *decode_stage = 4;
            if (BN_cmp(t, u) == 0 && !(BN_is_zero(x) && sign != 0)) {
                if (decode_stage != nullptr) *decode_stage = 5;
                if (BN_is_odd(x) != sign) BN_sub(x, p, x);
                out.x = BN_dup(x);
                out.y = BN_dup(y);
                ok = out.x != nullptr && out.y != nullptr;
            }
        }
    }
    BN_CTX_end(ctx);
    if (!ok) ed_point_free(out);
    return ok;
}

bool ed_add_points(const EdwardsPoint& a, const EdwardsPoint& b, EdwardsPoint& out,
                   const BIGNUM* p, const BIGNUM* d, BN_CTX* ctx) {
    BN_CTX_start(ctx);
    BIGNUM* x1y2 = BN_CTX_get(ctx);
    BIGNUM* x2y1 = BN_CTX_get(ctx);
    BIGNUM* y1y2 = BN_CTX_get(ctx);
    BIGNUM* x1x2 = BN_CTX_get(ctx);
    BIGNUM* num_x = BN_CTX_get(ctx);
    BIGNUM* num_y = BN_CTX_get(ctx);
    BIGNUM* t = BN_CTX_get(ctx);
    BIGNUM* den_x = BN_CTX_get(ctx);
    BIGNUM* den_y = BN_CTX_get(ctx);
    BIGNUM* inv = BN_CTX_get(ctx);
    BIGNUM* x3 = BN_CTX_get(ctx);
    BIGNUM* y3 = BN_CTX_get(ctx);
    bool ok = x1y2 != nullptr && x2y1 != nullptr && y1y2 != nullptr && x1x2 != nullptr
            && num_x != nullptr && num_y != nullptr && t != nullptr && den_x != nullptr
            && den_y != nullptr && inv != nullptr && x3 != nullptr && y3 != nullptr;
    if (ok) {
        BN_mod_mul(x1y2, a.x, b.y, p, ctx);
        BN_mod_mul(x2y1, b.x, a.y, p, ctx);
        BN_mod_add(num_x, x1y2, x2y1, p, ctx);
        BN_mod_mul(y1y2, a.y, b.y, p, ctx);
        BN_mod_mul(x1x2, a.x, b.x, p, ctx);
        BN_mod_add(num_y, y1y2, x1x2, p, ctx);
        BN_mod_mul(t, a.x, b.x, p, ctx);
        BN_mod_mul(t, t, d, p, ctx);
        BN_mod_mul(t, t, a.y, p, ctx);
        BN_mod_mul(t, t, b.y, p, ctx);
        BN_mod_add(den_x, t, BN_value_one(), p, ctx);
        BN_mod_sub(den_y, BN_value_one(), t, p, ctx);
        ok = BN_mod_inverse(inv, den_x, p, ctx) != nullptr;
        if (ok) BN_mod_mul(x3, num_x, inv, p, ctx);
        ok = ok && BN_mod_inverse(inv, den_y, p, ctx) != nullptr;
        if (ok) BN_mod_mul(y3, num_y, inv, p, ctx);
        if (ok) {
            out.x = BN_dup(x3);
            out.y = BN_dup(y3);
            ok = out.x != nullptr && out.y != nullptr;
        }
    }
    BN_CTX_end(ctx);
    if (!ok) ed_point_free(out);
    return ok;
}

bool ed_scalar_mul(const BIGNUM* scalar, const EdwardsPoint& point, EdwardsPoint& out,
                   const BIGNUM* p, const BIGNUM* d, BN_CTX* ctx) {
    EdwardsPoint acc;
    acc.x = BN_new();
    acc.y = BN_new();
    bool ok = acc.x != nullptr && acc.y != nullptr
            && BN_set_word(acc.x, 0) == 1 && BN_one(acc.y) == 1;
    const int bits = BN_num_bits(scalar);
    for (int i = bits - 1; ok && i >= 0; i--) {
        EdwardsPoint doubled;
        ok = ed_add_points(acc, acc, doubled, p, d, ctx);
        ed_point_free(acc);
        acc = doubled;
        if (ok && BN_is_bit_set(scalar, i)) {
            EdwardsPoint summed;
            ok = ed_add_points(acc, point, summed, p, d, ctx);
            ed_point_free(acc);
            acc = summed;
        }
    }
    if (ok) out = acc;
    else ed_point_free(acc);
    return ok;
}

bool ed25519_verify_bn(const unsigned char* pub, const unsigned char* msg, size_t msg_len,
                        const unsigned char* sig, size_t sig_len, int* stages = nullptr) {
    if (stages != nullptr) *stages = 0;
    if (sig_len != 64 || pub == nullptr) return false;
    BN_CTX* ctx = BN_CTX_new();
    if (ctx == nullptr) return false;
    BIGNUM* p = BN_new();
    BIGNUM* l = BN_new();
    BIGNUM* d = BN_new();
    BIGNUM* sqrt_m1 = BN_new();
    BIGNUM* sqrt_exp = BN_new();
    BIGNUM* s = nullptr;
    BIGNUM* k = nullptr;
    EdwardsPoint a{};
    EdwardsPoint r{};
    EdwardsPoint base{};
    EdwardsPoint sb{};
    EdwardsPoint ka{};
    EdwardsPoint sum{};
    unsigned char hash[64];
    unsigned char base_encoded[32];
    bool ok = p != nullptr && l != nullptr && d != nullptr && sqrt_m1 != nullptr
            && sqrt_exp != nullptr;
    if (ok) {
        ok = BN_hex2bn(&p, "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed") != 0
                && BN_hex2bn(&l, "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed") != 0
                && BN_hex2bn(&d, "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3") != 0
                && BN_hex2bn(&sqrt_m1, "2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0") != 0;
    }
    if (ok) {
        BN_copy(sqrt_exp, p);
        BN_add_word(sqrt_exp, 3);
        BN_rshift(sqrt_exp, sqrt_exp, 3);
        std::memcpy(base_encoded, "\x58", 1);
        std::memset(base_encoded + 1, 0x66, 31);
        int base_stage = 0;
        ok = ed_decode_point(base_encoded, base, p, d, sqrt_m1, sqrt_exp, ctx, &base_stage);
        if (!ok && stages != nullptr) *stages |= (base_stage << 8);
        if (ok && stages != nullptr) *stages |= 1;
    }
    if (ok) {
        EVP_MD_CTX* sha = EVP_MD_CTX_new();
        unsigned int hash_len = 0;
        bool hashed = sha != nullptr
                && EVP_DigestInit_ex(sha, EVP_sha512(), nullptr) == 1
                && EVP_DigestUpdate(sha, sig, 32) == 1
                && EVP_DigestUpdate(sha, pub, 32) == 1
                && EVP_DigestUpdate(sha, msg, msg_len) == 1
                && EVP_DigestFinal_ex(sha, hash, &hash_len) == 1
                && hash_len == 64;
        if (sha != nullptr) EVP_MD_CTX_free(sha);
        k = hashed ? BN_lebin2bn(hash, 64, nullptr) : nullptr;
        s = BN_lebin2bn(sig + 32, 32, nullptr);
        ok = k != nullptr && s != nullptr && BN_cmp(s, l) < 0;
        if (ok && stages != nullptr) *stages |= 2;
    }
    if (ok) {
        BN_CTX_start(ctx);
        BIGNUM* reduced = BN_CTX_get(ctx);
        ok = reduced != nullptr && BN_mod(reduced, k, l, ctx) == 1;
        if (ok) {
            BN_free(k);
            k = BN_dup(reduced);
            ok = k != nullptr;
        }
        BN_CTX_end(ctx);
    }
    if (ok) {
        ok = ed_decode_point(pub, a, p, d, sqrt_m1, sqrt_exp, ctx);
        if (ok && stages != nullptr) *stages |= 4;
    }
    if (ok) {
        ok = ed_decode_point(sig, r, p, d, sqrt_m1, sqrt_exp, ctx);
        if (ok && stages != nullptr) *stages |= 8;
    }
    if (ok) {
        ok = ed_scalar_mul(s, base, sb, p, d, ctx);
        if (ok && stages != nullptr) *stages |= 16;
    }
    if (ok) {
        ok = ed_scalar_mul(k, a, ka, p, d, ctx);
        if (ok && stages != nullptr) *stages |= 32;
    }
    if (ok) {
        ok = ed_add_points(r, ka, sum, p, d, ctx);
        if (ok && stages != nullptr) *stages |= 64;
    }
    if (ok) {
        ok = BN_cmp(sb.x, sum.x) == 0 && BN_cmp(sb.y, sum.y) == 0;
        if (ok && stages != nullptr) *stages |= 128;
    }
    ed_point_free(a);
    ed_point_free(r);
    ed_point_free(base);
    ed_point_free(sb);
    ed_point_free(ka);
    ed_point_free(sum);
    BN_free(p);
    BN_free(l);
    BN_free(d);
    BN_free(sqrt_m1);
    BN_free(sqrt_exp);
    BN_free(s);
    BN_free(k);
    BN_CTX_free(ctx);
    secure_wipe(hash, sizeof(hash));
    return ok;
}

bool ed25519_verify_independent(const unsigned char* msg, size_t msg_len,
                                const unsigned char* sig, size_t sig_len) {
    if (sig_len != 64 || g_pinned_ed_pub == nullptr) return false;
    // The second path only receives the raw public key captured at nativeSetAuthContext time;
    // it never calls EVP_DigestVerify / EVP_PKEY_verify.
    return ed25519_verify_bn(g_server_pub, msg, msg_len, sig, sig_len);
}
bool x25519_shared(const unsigned char* priv, const unsigned char* peer_pub,
                   unsigned char* out, size_t* out_len) {
    EVP_PKEY* priv_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv, 32);
    EVP_PKEY* peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_pub, 32);
    if (priv_key == nullptr || peer_key == nullptr) {
        if (priv_key) EVP_PKEY_free(priv_key);
        if (peer_key) EVP_PKEY_free(peer_key);
        return false;
    }
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv_key, nullptr);
    size_t len = *out_len;
    bool ok = ctx != nullptr
            && EVP_PKEY_derive_init(ctx) == 1
            && EVP_PKEY_derive_set_peer(ctx, peer_key) == 1
            && EVP_PKEY_derive(ctx, out, &len) == 1;
    if (ok) *out_len = len;
    if (ctx) EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv_key);
    EVP_PKEY_free(peer_key);
    return ok;
}

bool aes_gcm_decrypt(const unsigned char* key, const unsigned char* nonce, size_t nonce_len,
                     const unsigned char* ciphertext, size_t ciphertext_len,
                     const unsigned char* tag, size_t tag_len,
                     const unsigned char* aad, size_t aad_len,
                     unsigned char* out, size_t* out_len) {
    EVP_CIPHER_CTX* pooled = nullptr;
    EVP_CIPHER_CTX* ctx = nullptr;
    bool pooled_ctx = false;
    if (g_cipher_ctx_pool_ready) {
        pooled_ctx = acquire_cipher_ctx(&pooled);
        if (!pooled_ctx) return false;
        ctx = pooled;
    } else {
        ctx = EVP_CIPHER_CTX_new();
        if (ctx == nullptr) return false;
    }
    bool ok = false;
    int len = 0;
    int total = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1
            && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce_len), nullptr) == 1
            && EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) == 1) {
        if (aad_len == 0 || EVP_DecryptUpdate(ctx, nullptr, &len, aad, static_cast<int>(aad_len)) == 1) {
            if (EVP_DecryptUpdate(ctx, out, &len, ciphertext, static_cast<int>(ciphertext_len)) == 1) {
                total = len;
                if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag_len),
                                        const_cast<unsigned char*>(tag)) == 1
                        && EVP_DecryptFinal_ex(ctx, out + total, &len) == 1) {
                    total += len;
                    *out_len = static_cast<size_t>(total);
                    ok = true;
                }
            }
        }
    }
    if (pooled_ctx) release_cipher_ctx(pooled);
    else EVP_CIPHER_CTX_free(ctx);
    return ok;
}

std::vector<unsigned char> jbyte_array(JNIEnv* env, jbyteArray array) {
    std::vector<unsigned char> out;
    if (array == nullptr) return out;
    jsize len = env->GetArrayLength(array);
    if (len <= 0) return out;
    out.resize(static_cast<size_t>(len));
    env->GetByteArrayRegion(array, 0, len, reinterpret_cast<jbyte*>(out.data()));
    return out;
}

jbyteArray make_byte_array(JNIEnv* env, const std::vector<unsigned char>& data) {
    jbyteArray array = env->NewByteArray(static_cast<jsize>(data.size()));
    if (array != nullptr && !data.empty()) {
        env->SetByteArrayRegion(array, 0, static_cast<jsize>(data.size()),
                                reinterpret_cast<const jbyte*>(data.data()));
    }
    return array;
}

bool derive_kek_from(const unsigned char key[32], unsigned char out[32]) {
    const unsigned char info[] = "kek";
    return hkdf_sha256(key, 32,
                       reinterpret_cast<const unsigned char*>("chimera-kek-v1"), 14,
                       info, 3, out, 32);
}

bool derive_kek_locked(const HandleSlot& slot, unsigned char out[32]) {
    return derive_kek_from(slot.key, out);
}

bool derive_session_locked(const HandleSlot& slot, const unsigned char* nonce,
                           unsigned char out[32]) {
    unsigned char kek[32];
    if (!derive_kek_locked(slot, kek)) return false;
    const unsigned char info[] = "chimera/session/v1";
    bool ok = hkdf_sha256(kek, 32, nonce, 16, info, sizeof(info) - 1, out, 32);
    secure_wipe(kek, sizeof(kek));
    return ok;
}

uint32_t read_u32_be(const unsigned char* data) {
    return (static_cast<uint32_t>(data[0]) << 24)
            | (static_cast<uint32_t>(data[1]) << 16)
            | (static_cast<uint32_t>(data[2]) << 8)
            | static_cast<uint32_t>(data[3]);
}

uint64_t read_u64_be(const unsigned char* data) {
    uint64_t value = 0;
    for (int i = 0; i < 8; i++) value = (value << 8) | data[i];
    return value;
}

void append_u64_be(std::vector<unsigned char>& out, uint64_t value) {
    for (int i = 7; i >= 0; i--) out.push_back(static_cast<unsigned char>((value >> (i * 8)) & 0xff));
}

// ================================================================== B7 step 2 (native)
//
// op6 VM_CALL_NATIVE: opaque u16 index + argc + retKind + argc*32B slots + data region.
//   slot layout: [u32 BE offset into data][u32 BE length]; length==0 means an inline 8-byte value
//   (used for small integers such as VERIFY_RESULT_TAG's verify_result).
// op7 VERIFY_DECISION: tag32 only; native recomputes the AOT expected tag (result=1), writes handle
//   state (PENDING->VALID or POISON), returns 32 zero bytes.
// op8 AOT_VERIFY_TAG_REF: u64 BE result + session_const32 -> SHA-256 tag.
// op9 DECRYPT_DATA: fragment-runtime contract (kind/id/salt/nonce/aad/ciphertext|tag).

constexpr size_t kNativeFnCount = 6;
constexpr uint16_t kNativeFnVerifyEd25519 = 0x7A31;
constexpr uint16_t kNativeFnVerifyResultTag = 0xC40E;
constexpr uint16_t kNativeFnSha256 = 0x51B7;
constexpr uint16_t kNativeFnHmac = 0x2D93;
constexpr uint16_t kNativeFnHkdf = 0xE162;
constexpr uint16_t kNativeFnSessionNonce = 0x39C5;

constexpr size_t kMaxB7Params = 64 * 1024;

struct NativeArg {
    const unsigned char* data;
    size_t len;
};

struct NativeCallResult {
    unsigned char bytes[32];
    size_t len;
    bool ok;
};

typedef bool (*NativeFnPtr)(HandleSlot* slot, const NativeArg* args, size_t argc, NativeCallResult& out);

void write_u32_be(unsigned char* out, uint32_t value) {
    out[0] = static_cast<unsigned char>((value >> 24) & 0xff);
    out[1] = static_cast<unsigned char>((value >> 16) & 0xff);
    out[2] = static_cast<unsigned char>((value >> 8) & 0xff);
    out[3] = static_cast<unsigned char>(value & 0xff);
}

void write_u64_be(unsigned char* out, uint64_t value) {
    for (int i = 0; i < 8; i++) {
        out[i] = static_cast<unsigned char>((value >> ((7 - i) * 8)) & 0xff);
    }
}

bool derive_session_const_locked(const HandleSlot& slot, unsigned char out[32]) {
    const unsigned char info[] = "chimera/session-const/v1";
    return hkdf_sha256(slot.key, 32, slot.nonce, 16, info, sizeof(info) - 1, out, 32);
}

bool derive_session_nonce_locked(const HandleSlot& slot, unsigned char out[32]) {
    const unsigned char info[] = "chimera/session-nonce/v1";
    return hkdf_sha256(slot.key, 32, slot.nonce, 16, info, sizeof(info) - 1, out, 32);
}

void compute_verify_tag(uint64_t verify_result, const unsigned char nonce[32],
                        const unsigned char session_const[32], unsigned char out[32]) {
    unsigned char seed[sizeof("chimera/verify-tag/v1") - 1 + 8 + 32 + 32];
    size_t n = 0;
    const char prefix[] = "chimera/verify-tag/v1";
    std::memcpy(seed, prefix, sizeof(prefix) - 1);
    n += sizeof(prefix) - 1;
    write_u64_be(seed + n, verify_result);
    n += 8;
    std::memcpy(seed + n, nonce, 32);
    n += 32;
    std::memcpy(seed + n, session_const, 32);
    n += 32;
    SHA256(seed, n, out);
    secure_wipe(seed, sizeof(seed));
}

// B7-2/B2: handle value mixes the verified result with the VM session nonce bits.
uint64_t handle_mix_bits(uint64_t verify_result, const unsigned char session_nonce[32]) {
    unsigned char seed[sizeof("chimera/handle-mix/v1") - 1 + 8 + 32];
    size_t n = 0;
    const char prefix[] = "chimera/handle-mix/v1";
    std::memcpy(seed, prefix, sizeof(prefix) - 1);
    n += sizeof(prefix) - 1;
    write_u64_be(seed + n, verify_result);
    n += 8;
    std::memcpy(seed + n, session_nonce, 32);
    n += 32;
    unsigned char digest[32];
    SHA256(seed, n, digest);
    secure_wipe(seed, sizeof(seed));
    uint64_t value = 0;
    std::memcpy(&value, digest, sizeof(value));
    secure_wipe(digest, sizeof(digest));
    return value;
}

bool native_fn_verify_ed25519(HandleSlot* slot, const NativeArg* args, size_t argc,
                              NativeCallResult& out) {
    if (slot == nullptr || argc < 2) return false;
    int result = 0;
    if (g_force_verify_result_enabled) {
        result = g_force_verify_result;
    } else if (args[1].len == 64) {
        result = chimera_b7_primary_verify(args[0].data, args[0].data, args[0].len,
                                           args[1].data, 64);
    } else if (argc >= 3 && args[0].len == 32 && args[1].len == 32 && args[2].len == 32) {
        unsigned char signature[64];
        std::memcpy(signature, args[1].data, 32);
        std::memcpy(signature + 32, args[2].data, 32);
        result = ed25519_verify(args[0].data, args[0].data, 32, signature, 64) ? 1 : 0;
        secure_wipe(signature, sizeof(signature));
    } else {
        return false;
    }
    slot->verify_result = static_cast<uint32_t>(result);
    out.len = 0;
    out.ok = true;
    return true;
}

bool native_fn_verify_result_tag(HandleSlot* slot, const NativeArg* args, size_t argc,
                                 NativeCallResult& out) {
    if (slot == nullptr || argc < 2 || args[1].len != 32) return false;
    uint64_t result = 0;
    const size_t take = args[0].len >= 8 ? 8 : args[0].len;
    for (size_t i = 0; i < take; i++) result = (result << 8) | args[0].data[i];
    unsigned char session_const[32];
    if (!derive_session_const_locked(*slot, session_const)) return false;
    compute_verify_tag(result, args[1].data, session_const, out.bytes);
    secure_wipe(session_const, sizeof(session_const));
    out.len = 32;
    out.ok = true;
    return true;
}

// Local, allocation-free SHA-256 for the B7 CALL_NATIVE path. OpenSSL 3's one-shot SHA256()
// performs provider fetch/refcount allocations (B7-6 no-heap violation), so the fixed-slot
// CALL_NATIVE(2) path uses this stack-only implementation.
struct B7Sha256 {
    uint32_t state[8];
    uint64_t bit_length;
    unsigned char buffer[64];
    size_t buffer_len;
};

constexpr uint32_t kB7Sha256K[64] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
        0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
        0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
        0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
        0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
        0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
        0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
        0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

uint32_t b7_rotr(uint32_t value, uint32_t bits) {
    return (value >> bits) | (value << (32 - bits));
}

void b7_sha256_block(B7Sha256& ctx, const unsigned char block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = (static_cast<uint32_t>(block[i * 4]) << 24)
                | (static_cast<uint32_t>(block[i * 4 + 1]) << 16)
                | (static_cast<uint32_t>(block[i * 4 + 2]) << 8)
                | static_cast<uint32_t>(block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        const uint32_t s0 = b7_rotr(w[i - 15], 7) ^ b7_rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const uint32_t s1 = b7_rotr(w[i - 2], 17) ^ b7_rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = ctx.state[0], b = ctx.state[1], c = ctx.state[2], d = ctx.state[3];
    uint32_t e = ctx.state[4], f = ctx.state[5], g = ctx.state[6], h = ctx.state[7];
    for (int i = 0; i < 64; i++) {
        const uint32_t s1 = b7_rotr(e, 6) ^ b7_rotr(e, 11) ^ b7_rotr(e, 25);
        const uint32_t ch = (e & f) ^ (~e & g);
        const uint32_t temp1 = h + s1 + ch + kB7Sha256K[i] + w[i];
        const uint32_t s0 = b7_rotr(a, 2) ^ b7_rotr(a, 13) ^ b7_rotr(a, 22);
        const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t temp2 = s0 + maj;
        h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
    }
    ctx.state[0] += a; ctx.state[1] += b; ctx.state[2] += c; ctx.state[3] += d;
    ctx.state[4] += e; ctx.state[5] += f; ctx.state[6] += g; ctx.state[7] += h;
}

void b7_sha256_init(B7Sha256& ctx) {
    static const uint32_t initial[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
            0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
    for (int i = 0; i < 8; i++) ctx.state[i] = initial[i];
    ctx.bit_length = 0;
    ctx.buffer_len = 0;
}

void b7_sha256_update(B7Sha256& ctx, const unsigned char* data, size_t length) {
    ctx.bit_length += static_cast<uint64_t>(length) * 8ULL;
    while (length > 0) {
        const size_t take = length < 64 - ctx.buffer_len ? length : 64 - ctx.buffer_len;
        std::memcpy(ctx.buffer + ctx.buffer_len, data, take);
        ctx.buffer_len += take;
        data += take;
        length -= take;
        if (ctx.buffer_len == 64) {
            b7_sha256_block(ctx, ctx.buffer);
            ctx.buffer_len = 0;
        }
    }
}

void b7_sha256_final(B7Sha256& ctx, unsigned char out[32]) {
    const uint64_t bit_length = ctx.bit_length;
    unsigned char pad = 0x80;
    b7_sha256_update(ctx, &pad, 1);
    unsigned char zero = 0;
    while (ctx.buffer_len != 56) b7_sha256_update(ctx, &zero, 1);
    unsigned char length_bytes[8];
    for (int i = 0; i < 8; i++) length_bytes[i] = static_cast<unsigned char>((bit_length >> (56 - i * 8)) & 0xff);
    b7_sha256_update(ctx, length_bytes, 8);
    for (int i = 0; i < 8; i++) {
        out[i * 4] = static_cast<unsigned char>((ctx.state[i] >> 24) & 0xff);
        out[i * 4 + 1] = static_cast<unsigned char>((ctx.state[i] >> 16) & 0xff);
        out[i * 4 + 2] = static_cast<unsigned char>((ctx.state[i] >> 8) & 0xff);
        out[i * 4 + 3] = static_cast<unsigned char>(ctx.state[i] & 0xff);
    }
    secure_wipe(&ctx, sizeof(ctx));
}

void b7_sha256(const unsigned char* data, size_t length, unsigned char out[32]) {
    B7Sha256 ctx;
    b7_sha256_init(ctx);
    b7_sha256_update(ctx, data, length);
    b7_sha256_final(ctx, out);
}
bool native_fn_sha256(HandleSlot*, const NativeArg* args, size_t argc, NativeCallResult& out) {
    if (argc < 1) return false;
    b7_sha256(args[0].data, args[0].len, out.bytes);
    out.len = 32;
    out.ok = true;
    return true;
}

bool native_fn_hmac(HandleSlot*, const NativeArg* args, size_t argc, NativeCallResult& out) {
    if (argc < 2 || args[0].len > 512) return false;
    unsigned int len = 0;
    const bool ok = HMAC(EVP_sha256(), args[0].data, static_cast<int>(args[0].len),
                         args[1].data, args[1].len, out.bytes, &len) != nullptr
            && len == 32;
    out.len = ok ? 32 : 0;
    out.ok = ok;
    return ok;
}

bool native_fn_hkdf(HandleSlot*, const NativeArg* args, size_t argc, NativeCallResult& out) {
    if (argc < 3) return false;
    const bool ok = hkdf_sha256(args[0].data, args[0].len, args[1].data, args[1].len,
                                args[2].data, args[2].len, out.bytes, 32);
    out.len = ok ? 32 : 0;
    out.ok = ok;
    return ok;
}

bool native_fn_session_nonce(HandleSlot* slot, const NativeArg*, size_t, NativeCallResult& out) {
    if (slot == nullptr) return false;
    if (!derive_session_nonce_locked(*slot, out.bytes)) return false;
    out.len = 32;
    out.ok = true;
    return true;
}

const struct NativeFnEntry {
    uint16_t opaque_index;
    NativeFnPtr fn;
} g_native_fn_table[kNativeFnCount] = {
        {kNativeFnVerifyEd25519, native_fn_verify_ed25519},
        {kNativeFnVerifyResultTag, native_fn_verify_result_tag},
        {kNativeFnSha256, native_fn_sha256},
        {kNativeFnHmac, native_fn_hmac},
        {kNativeFnHkdf, native_fn_hkdf},
        {kNativeFnSessionNonce, native_fn_session_nonce},
};

bool invoke_native_fn(uint16_t opaque_index, HandleSlot* slot, const NativeArg* args,
                      size_t argc, NativeCallResult& out) {
    out.len = 0;
    out.ok = false;
    for (size_t i = 0; i < kNativeFnCount; i++) {
        if (g_native_fn_table[i].opaque_index == opaque_index) {
            return g_native_fn_table[i].fn(slot, args, argc, out);
        }
    }
    return false;
}

bool compute_b7_call_native(HandleSlot& slot, const unsigned char* params, size_t length,
                            unsigned char* out, size_t out_cap, size_t* out_len) {
    if (length < 5) return false;
    const uint16_t index = static_cast<uint16_t>((params[1] << 8) | params[2]);
    const size_t argc = params[3];
    const size_t ret_kind = params[4];
    if (argc > 8 || 5 + argc * 32 > length) return false;
    NativeArg args[8] = {};
    for (size_t i = 0; i < argc; i++) {
        args[i].data = params + 5 + i * 32;  // fixed 32B VM slots; byte[] fills the whole slot
        args[i].len = 32;
    }
    if (index == kNativeFnVerifyResultTag && argc >= 1) {
        args[0].data = params + 5 + 24;  // numeric value in the last 8 bytes, big-endian
        args[0].len = 8;
    }
    NativeCallResult result{};
    if (!invoke_native_fn(index, &slot, args, argc, result) || !result.ok) return false;
    size_t want = 0;
    switch (ret_kind) {
        case 0: want = 4; break;           // int
        case 1: want = 8; break;           // long
        case 2: want = 8; break;           // double (raw bits)
        case 3: want = result.len; break;  // raw byte[] (32B for hash/tag/HMAC/HKDF/nonce)
        default: want = 0; break;          // void -> 0 bytes
    }
    if (want > out_cap) return false;
    std::memset(out, 0, want);
    std::memcpy(out, result.bytes, result.len < want ? result.len : want);
    *out_len = want;
    secure_wipe(result.bytes, sizeof(result.bytes));
    return true;
}

bool compute_b7_verify_decision(HandleSlot& slot, const unsigned char* params, size_t length) {
    if (length < 33) return false;
    unsigned char nonce[32];
    unsigned char session_const[32];
    unsigned char expected[32];
    if (!derive_session_nonce_locked(slot, nonce)
            || !derive_session_const_locked(slot, session_const)) {
        return false;
    }
    compute_verify_tag(slot.verify_result, nonce, session_const, expected);
    const bool matches = CRYPTO_memcmp(expected, params + 1, 32) == 0;
    secure_wipe(expected, sizeof(expected));
    secure_wipe(nonce, sizeof(nonce));
    secure_wipe(session_const, sizeof(session_const));
    if (matches && slot.state == kHandlePending) slot.state = kHandleValid;
    else if (!matches) slot.state = kHandlePoison;
    return true;
}

// AOT-side decision helper: a forced EVP_DigestVerify result alone cannot promote a handle;
// the independent EVP_PKEY_verify result must also be 1 (B7-2 native self-test; real Frida
// confirmation remains unexecuted and is reported as such).
void apply_verify_decision_locked(HandleSlot& slot, const unsigned char tag[32],
                                  const unsigned char nonce[32],
                                  const unsigned char session_const[32],
                                  int independent_result) {
    unsigned char expected[32];
    compute_verify_tag(slot.verify_result, nonce, session_const, expected);
    const bool matches = independent_result == 1
            && CRYPTO_memcmp(expected, tag, 32) == 0;
    secure_wipe(expected, sizeof(expected));
    if (matches) slot.state = kHandleValid;
    else slot.state = kHandlePoison;
}

bool compute_b7_verify_tag_ref(HandleSlot& slot, const unsigned char* params, size_t length,
                               unsigned char* out, size_t out_cap, size_t* out_len) {
    if (length < 1 + 32 + 8 || out_cap < 32) return false;
    uint64_t result = 0;
    for (int i = 0; i < 8; i++) result = (result << 8) | params[1 + 32 + i];
    unsigned char session_const[32];
    if (!derive_session_const_locked(slot, session_const)) return false;
    compute_verify_tag(result, params + 1, session_const, out);
    secure_wipe(session_const, sizeof(session_const));
    *out_len = 32;
    return true;
}
// op9 DECRYPT_DATA (fragment-runtime contract, lead-frozen):
// [u8 9][kindLen][kind][u32 id][saltLen][salt][12B nonce][u16 aadLen][aad][u32 ctLen][ct|tag]
bool compute_b7_decrypt_data(const HandleSlot& slot, const unsigned char* params, size_t length,
                             unsigned char* out, size_t out_cap, size_t* out_len) {
    size_t off = 1;
    if (off >= length) return false;
    const size_t kind_len = params[off++];
    if (kind_len == 0 || kind_len > 16 || off + kind_len + 4 + 1 + 12 + 2 + 4 > length) return false;
    const unsigned char* kind = params + off;
    off += kind_len;
    uint32_t id = 0;
    for (int i = 0; i < 4; i++) id = (id << 8) | params[off + i];
    off += 4;
    const size_t salt_len = params[off++];
    if (salt_len > 64 || off + salt_len + 12 + 2 > length) return false;
    const unsigned char* salt = params + off;
    off += salt_len;
    const unsigned char* nonce = params + off;
    off += 12;
    const size_t aad_len = (static_cast<size_t>(params[off]) << 8) | params[off + 1];
    off += 2;
    if (aad_len > 4096 || off + aad_len + 4 > length) return false;
    const unsigned char* aad = params + off;
    off += aad_len;
    uint32_t ct_len = 0;
    for (int i = 0; i < 4; i++) ct_len = (ct_len << 8) | params[off + i];
    off += 4;
    if (ct_len < 16 || ct_len > 48 * 1024 || off + ct_len > length) return false;
    const unsigned char* ct = params + off;

    char info[64];
    size_t info_len = 0;
    const char prefix[] = "chimera/v1/";
    std::memcpy(info, prefix, sizeof(prefix) - 1);
    info_len = sizeof(prefix) - 1;
    std::memcpy(info + info_len, kind, kind_len);
    info_len += kind_len;
    info[info_len++] = '/';
    char digits[12];
    int digit_count = 0;
    if (id == 0) digits[digit_count++] = '0';
    while (id != 0) { digits[digit_count++] = static_cast<char>('0' + (id % 10)); id /= 10; }
    for (int i = digit_count - 1; i >= 0; i--) info[info_len++] = digits[i];
    info[info_len] = '\0';

    SlotKey resource_key(slot);
    if (!resource_key.ok) {
        return false;
    }
    unsigned char kek[32];
    if (!derive_kek_from(resource_key.data(), kek)) {
        return false;
    }
    unsigned char item_key[32];
    const bool derived = hkdf_sha256(kek, 32, salt, salt_len,
                                     reinterpret_cast<const unsigned char*>(info), info_len,
                                     item_key, 32);
    secure_wipe(kek, sizeof(kek));
    if (!derived) {
        secure_wipe(item_key, sizeof(item_key));
        return false;
    }
    const size_t plain_cap = static_cast<size_t>(ct_len) - 16;
    if (plain_cap > out_cap) {
        secure_wipe(item_key, sizeof(item_key));
        return false;
    }
    size_t plain_len = 0;
    const bool decrypted = aes_gcm_decrypt(item_key, nonce, 12, ct, plain_cap,
                                           ct + plain_cap, 16, aad, aad_len,
                                           out, &plain_len);
    secure_wipe(item_key, sizeof(item_key));
    if (!decrypted) {
        return false;
    }
    *out_len = plain_len;
    return true;
}

// op10 RUN_DECISION_PROGRAM: release PENDING closure. transcript/signature never cross JNI; the
// decision re-verifies with the independent BN/SHA-512 path (not EVP_DigestVerify) and writes only
// the handle state. Always returns 32 zero bytes for a non-zero handle.
bool compute_b7_decision_program(HandleSlot& slot, const unsigned char* params, size_t length,
                                 unsigned char* out, size_t out_cap, size_t* out_len) {
    if (length < 2 || params[1] != 0 || out_cap < 32) return false;
    std::memset(out, 0, 32);
    *out_len = 32;
    if (slot.state == kHandlePoison) return true;
    if (slot.transcript_len == 0 || slot.transcript_len > sizeof(slot.transcript)
            || g_pinned_ed_pub == nullptr) {
        slot.state = kHandlePoison;
        return true;
    }
    int independent_result = ed25519_verify_bn(g_server_pub, slot.transcript,
                                               slot.transcript_len, slot.signature, 64) ? 1 : 0;


    unsigned char nonce[32];
    unsigned char session_const[32];
    if (independent_result != 1
            || !derive_session_nonce_locked(slot, nonce)
            || !derive_session_const_locked(slot, session_const)) {
        slot.state = kHandlePoison;
        secure_wipe(nonce, sizeof(nonce));
        secure_wipe(session_const, sizeof(session_const));
        return true;
    }
    unsigned char tag[32];
    compute_verify_tag(slot.verify_result, nonce, session_const, tag);
    apply_verify_decision_locked(slot, tag, nonce, session_const, independent_result);
    secure_wipe(tag, sizeof(tag));
    secure_wipe(nonce, sizeof(nonce));
    secure_wipe(session_const, sizeof(session_const));
    return true;
}

bool compute_b7_locked(HandleSlot& slot, const unsigned char* params, size_t length,
                       unsigned char* out, size_t out_cap, size_t* out_len) {
    if (length < 1) return false;
    switch (params[0]) {
        case 6: return compute_b7_call_native(slot, params, length, out, out_cap, out_len);
        case 7: {
            if (!compute_b7_verify_decision(slot, params, length)) return false;
            const size_t zeros = out_cap < 32 ? out_cap : 32;
            std::memset(out, 0, zeros);
            *out_len = zeros;
            return zeros == 32;
        }
        case 8: return compute_b7_verify_tag_ref(slot, params, length, out, out_cap, out_len);
        case 9: return compute_b7_decrypt_data(slot, params, length, out, out_cap, out_len);
        case 10: return compute_b7_decision_program(slot, params, length, out, out_cap, out_len);
        default: return false;
    }
}

// params: [op:u8][payload]
//   1 DERIVE_ITEM: u8 kindLen, kind bytes, u32 id, u8 saltLen, salt bytes -> 32B
//   2 HMAC:        u32 dataLen, data bytes -> 32B
//   3 SESSION:     16B nonce -> 32B
//   4 DYNAMIC:     16B nonce -> 8B
//   5 CANARY:      -> 8B (1 valid / 0 invalid)
std::vector<unsigned char> compute_locked(const HandleSlot& slot,
                                          const unsigned char* params, size_t length) {
    if (length < 1) return std::vector<unsigned char>();
    const unsigned char op = params[0];
    const unsigned char* p = params + 1;
    size_t left = length - 1;

    if (op == 5) {
        std::vector<unsigned char> result;
        append_u64_be(result, slot.state == kHandleValid ? 1ULL : 0ULL);
        return result;
    }

    if (op == 1) {
        if (left < 2) return std::vector<unsigned char>();
        size_t kind_len = p[0];
        p += 1;
        left -= 1;
        if (left < kind_len + 4 + 1) return std::vector<unsigned char>();
        std::string kind(reinterpret_cast<const char*>(p), kind_len);
        p += kind_len;
        left -= kind_len;
        uint32_t id = read_u32_be(p);
        p += 4;
        left -= 4;
        size_t salt_len = p[0];
        p += 1;
        left -= 1;
        if (left < salt_len) return std::vector<unsigned char>();
        unsigned char kek[32];
        if (!derive_kek_locked(slot, kek)) return std::vector<unsigned char>();
        std::string info = "chimera/v1/" + kind + "/" + std::to_string(id);
        unsigned char out[32];
        bool ok = hkdf_sha256(kek, 32, p, salt_len,
                              reinterpret_cast<const unsigned char*>(info.data()), info.size(),
                              out, 32);
        secure_wipe(kek, sizeof(kek));
        if (!ok) return std::vector<unsigned char>();
        return std::vector<unsigned char>(out, out + 32);
    }

    if (op == 2) {
        if (left < 4) return std::vector<unsigned char>();
        uint32_t data_len = read_u32_be(p);
        p += 4;
        left -= 4;
        if (left < data_len) return std::vector<unsigned char>();
        unsigned char kek[32];
        if (!derive_kek_locked(slot, kek)) return std::vector<unsigned char>();
        unsigned char out[32];
        unsigned int out_len = 0;
        bool ok = HMAC(EVP_sha256(), kek, 32, p, data_len, out, &out_len) != nullptr
                && out_len == 32;
        secure_wipe(kek, sizeof(kek));
        if (!ok) return std::vector<unsigned char>();
        return std::vector<unsigned char>(out, out + 32);
    }

    if (op == 3 || op == 4) {
        if (left < 16) return std::vector<unsigned char>();
        unsigned char session[32];
        if (!derive_session_locked(slot, p, session)) return std::vector<unsigned char>();
        if (op == 3) {
            std::vector<unsigned char> out(session, session + 32);
            secure_wipe(session, sizeof(session));
            return out;
        }
        const unsigned char info[] = "chimera/dynamic-key/v1";
        unsigned char seed[32 + 16 + sizeof(info) - 1];
        std::memcpy(seed, session, 32);
        std::memcpy(seed + 32, p, 16);
        std::memcpy(seed + 48, info, sizeof(info) - 1);
        unsigned char digest[32];
        SHA256(seed, sizeof(seed), digest);
        std::vector<unsigned char> out(digest, digest + 8);
        secure_wipe(session, sizeof(session));
        secure_wipe(seed, sizeof(seed));
        return out;
    }
    return std::vector<unsigned char>();
}

// ================================================================== S5 native support
// Hidden-class registration/verification, anti-dump probe, and self-extract payload helpers.

// ---------------------------------------------------------------- S5 hidden-class registry
// 4096 slots (128 KiB BSS): S5 obfuscates thousands of fragments per build; a 64-slot registry
// would fail-closed after the first 64 registrations.
constexpr size_t kS5HiddenRegistrySize = 4096;
unsigned char g_s5_hidden_registry[kS5HiddenRegistrySize][32];
size_t g_s5_hidden_registry_count = 0;

// Iterate every method of a hidden class and compare each method's JVMTI GetBytecodes SHA-256
// against expected. Returns 1=match, 0=no match, -1=JVMTI unavailable/no method bytes.
int hidden_class_method_hash_any(jclass klass, const unsigned char expected[32], bool* saw_any) {
    if (saw_any != nullptr) *saw_any = false;
    if (g_jvmti == nullptr || !g_jvmti_bytecodes || klass == nullptr) return -1;
    jint method_count = 0;
    jmethodID* methods = nullptr;
    if (g_jvmti->GetClassMethods(klass, &method_count, &methods) != JVMTI_ERROR_NONE
            || methods == nullptr || method_count <= 0) {
        if (methods != nullptr) g_jvmti->Deallocate(reinterpret_cast<unsigned char*>(methods));
        return -1;
    }
    int result = 0;
    bool saw = false;
    for (jint i = 0; i < method_count; i++) {
        unsigned char* code = nullptr;
        jint code_len = 0;
        if (g_jvmti->GetBytecodes(methods[i], &code_len, &code) != JVMTI_ERROR_NONE
                || code == nullptr || code_len <= 0) {
            continue;
        }
        saw = true;
        unsigned char digest[32];
        SHA256(code, static_cast<size_t>(code_len), digest);
        if (CRYPTO_memcmp(digest, expected, sizeof(digest)) == 0) result = 1;
        secure_wipe(digest, sizeof(digest));
        g_jvmti->Deallocate(code);
        if (result == 1) break;
    }
    g_jvmti->Deallocate(reinterpret_cast<unsigned char*>(methods));
    if (saw_any != nullptr) *saw_any = saw;
    return saw ? result : -1;
}

bool hidden_registry_add(const unsigned char hash[32]) {
    for (size_t i = 0; i < g_s5_hidden_registry_count; i++) {
        if (std::memcmp(g_s5_hidden_registry[i], hash, 32) == 0) return true;
    }
    if (g_s5_hidden_registry_count >= kS5HiddenRegistrySize) {
        // Fixed-size, fail-closed: never evict an approved hash.
        return false;
    }
    std::memcpy(g_s5_hidden_registry[g_s5_hidden_registry_count++], hash, 32);
    return true;
}

int hidden_registry_contains_class(jclass klass) {
    if (g_jvmti == nullptr || !g_jvmti_bytecodes || klass == nullptr) return -1;
    jint method_count = 0;
    jmethodID* methods = nullptr;
    if (g_jvmti->GetClassMethods(klass, &method_count, &methods) != JVMTI_ERROR_NONE
            || methods == nullptr || method_count <= 0) {
        if (methods != nullptr) g_jvmti->Deallocate(reinterpret_cast<unsigned char*>(methods));
        return -1;
    }
    bool saw = false;
    bool found = false;
    for (jint i = 0; i < method_count && !found; i++) {
        unsigned char* code = nullptr;
        jint code_len = 0;
        if (g_jvmti->GetBytecodes(methods[i], &code_len, &code) != JVMTI_ERROR_NONE
                || code == nullptr || code_len <= 0) {
            continue;
        }
        saw = true;
        unsigned char digest[32];
        SHA256(code, static_cast<size_t>(code_len), digest);
        for (size_t r = 0; r < g_s5_hidden_registry_count; r++) {
            if (CRYPTO_memcmp(digest, g_s5_hidden_registry[r], 32) == 0) found = true;
        }
        secure_wipe(digest, sizeof(digest));
        g_jvmti->Deallocate(code);
    }
    g_jvmti->Deallocate(reinterpret_cast<unsigned char*>(methods));
    return saw ? (found ? 1 : 0) : -1;
}

// ---------------------------------------------------------------- S5 anti-dump probe
volatile LONG g_s5_anti_dump_signal_count = 0;
volatile LONG g_s5_anti_dump_last_mask = 0;
uint64_t g_s5_anti_dump_last_check_ms = 0;

typedef LONG(NTAPI* S5NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
constexpr ULONG kS5SystemExtendedHandleInformation = 64;
struct S5HandleEntryEx {
    void* object;
    ULONG_PTR unique_process_id;
    ULONG_PTR handle_value;
    ULONG granted_access;
    USHORT creator_back_trace_index;
    USHORT object_type_index;
    ULONG handle_attributes;
    ULONG reserved;
};
struct S5HandleInfoEx {
    ULONG_PTR number_of_handles;
    ULONG_PTR reserved;
    S5HandleEntryEx handles[1];
};

bool s5_suspicious_module_loaded() {
    HMODULE modules[1024];
    DWORD needed = 0;
    if (EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &needed) == 0) {
        return false;
    }
    const DWORD count = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < count && i < 1024; i++) {
        char name[MAX_PATH] = {};
        if (GetModuleBaseNameA(GetCurrentProcess(), modules[i], name, sizeof(name)) == 0) continue;
        if (contains_ci(name, "frida") || contains_ci(name, "gum-")
                || contains_ci(name, "libgadget") || contains_ci(name, "libfrida")) {
            return true;
        }
    }
    return false;
}

bool s5_process_looks_like_debugger(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == nullptr) return false;
    char path[1024] = {};
    DWORD size = static_cast<DWORD>(sizeof(path));
    bool suspicious = false;
    if (QueryFullProcessImageNameA(process, 0, path, &size) != 0 && size > 0) {
        const char* name = path;
        for (DWORD i = 0; i + 1 < size; i++) {
            if (path[i] == '\\' || path[i] == '/') name = path + i + 1;
        }
        static const char* kTools[] = {
                "x64dbg", "x32dbg", "ida", "ida64", "ida32", "ollydbg", "windbg", "cdb",
                "gdb", "lldb", "frida", "gum", "cheatengine", "processhacker",
                "systeminformer", "procdump", "dump", "wireshark"};
        for (const char* tool : kTools) {
            if (contains_ci(name, tool)) { suspicious = true; break; }
        }
    }
    CloseHandle(process);
    return suspicious;
}

// Returns telemetry mask: 2 = a known debugger/dump tool owns a PROCESS_VM_READ handle to us,
// 16 = some other external process holds a VM_READ handle (common for EDR/AV; telemetry only).
int s5_remote_vm_read_mask(int* generic_readers) {
    *generic_readers = 0;
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll == nullptr) return 0;
    auto query = reinterpret_cast<S5NtQuerySystemInformation>(
            GetProcAddress(ntdll, "NtQuerySystemInformation"));
    if (query == nullptr) return 0;
    const DWORD self_pid = GetCurrentProcessId();
    HANDLE self_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, self_pid);
    if (self_handle == nullptr) return 0;
    std::vector<unsigned char> buffer(1 << 20);
    LONG status = -1;
    for (int attempt = 0; attempt < 4; attempt++) {
        ULONG needed = 0;
        status = query(kS5SystemExtendedHandleInformation, buffer.data(),
                       static_cast<ULONG>(buffer.size()), &needed);
        if (status == 0) break;
        if (needed <= buffer.size() || needed > (64u << 20)) break;
        buffer.resize(needed + (64u << 10));
    }
    int mask = 0;
    if (status == 0) {
        auto* info = reinterpret_cast<S5HandleInfoEx*>(buffer.data());
        void* self_object = nullptr;
        for (ULONG_PTR i = 0; i < info->number_of_handles; i++) {
            const S5HandleEntryEx& entry = info->handles[i];
            if (entry.unique_process_id == self_pid
                    && entry.handle_value == reinterpret_cast<ULONG_PTR>(self_handle)) {
                self_object = entry.object;
                break;
            }
        }
        if (self_object != nullptr) {
            for (ULONG_PTR i = 0; i < info->number_of_handles; i++) {
                const S5HandleEntryEx& entry = info->handles[i];
                if (entry.unique_process_id == self_pid || entry.object != self_object
                        || (entry.granted_access & PROCESS_VM_READ) == 0) {
                    continue;
                }
                (*generic_readers)++;
                if (s5_process_looks_like_debugger(static_cast<DWORD>(entry.unique_process_id))) {
                    mask |= 2;
                } else {
                    mask |= 16;
                }
            }
        }
    }
    CloseHandle(self_handle);
    return mask;
}

int s5_anti_dump_scan() {
    int mask = 0;
    BOOL remote_debugger = FALSE;
    if (IsDebuggerPresent() != 0 || (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_debugger)
            != 0 && remote_debugger != 0)) {
        mask |= 1;
    }
    int generic_readers = 0;
    mask |= s5_remote_vm_read_mask(&generic_readers);
    if (s5_suspicious_module_loaded()) mask |= 4;
    if (g_test_mode) mask |= 8;
    InterlockedExchange(&g_s5_anti_dump_last_mask, mask);
    if ((mask & 7) != 0) InterlockedIncrement(&g_s5_anti_dump_signal_count);
    return mask;
}

int s5_anti_dump_cached_mask() {
    const uint64_t now = GetTickCount64();
    if (g_s5_anti_dump_last_check_ms != 0 && now >= g_s5_anti_dump_last_check_ms
            && now - g_s5_anti_dump_last_check_ms < 1000) {
        return static_cast<int>(InterlockedCompareExchange(&g_s5_anti_dump_last_mask, 0, 0));
    }
    const int mask = s5_anti_dump_scan();
    g_s5_anti_dump_last_check_ms = now;
    return mask;
}

bool s5_anti_dump_should_poison() {
#if defined(CHIMERA_DEV_BUILD)
    // Dev/test builds: telemetry only; never poison on the probe so the test suite stays stable.
    return false;
#else
    // Release: only stricter. Probe failure is not a bypass: if it cannot inspect handles/modules,
    // the existing debugger/anti-debug path still applies; a detected remote reader or suspicious
    // module poisons. (No 'unavailable => allow' branch.)
    // Policy (decided 2026-10-22 by the product owner): an attached debugger is treated as hostile
    // too - "nobody debug-attaches a game they are just playing". Bits:
    //   1 = local/remote debugger (IsDebuggerPresent / CheckRemoteDebuggerPresent / DebugPort),
    //   2 = a known dumper holding a VM_READ handle, 4 = injected instrumentation module (Frida/gum).
    // A generic EDR/AV reader (bit 16) stays telemetry: AV ships on millions of machines and must
    // not cost a legitimate player the launch.
    return (s5_anti_dump_cached_mask() & (1 | 2 | 4)) != 0;
#endif
}

// ---------------------------------------------------------------- S5 self-extract payload
// Overlay format appended to chimera_auth.dll (little-endian):
//   ciphertext[payload_len] || nonce[12] || tag[16] || "CHPY" || u32 version(1) || u64 payload_len
// The native side reads its own file (the loader maps only the image, not the overlay).
constexpr size_t kS5PayloadFooterSize = 12 + 16 + 4 + 4 + 8;

// Java calls nativeSetPayloadContext(envSalt) after ensureEnv; the salt is only used to derive
// the overlay payload key from the handle's ResourceKey (HKDF salt=envSalt, info="chimera/v1/payload").
unsigned char g_s5_payload_env_salt[64];
size_t g_s5_payload_env_salt_len = 0;

bool s5_derive_payload_key(const HandleSlot& slot, unsigned char out[32]) {
    if (g_s5_payload_env_salt_len == 0) return false;  // fail closed until Java provides envSalt
    SlotKey resource_key(slot);
    if (!resource_key.ok) return false;
    const unsigned char info[] = "chimera/v1/payload";
    return hkdf_sha256(resource_key.data(), 32, g_s5_payload_env_salt, g_s5_payload_env_salt_len,
                       info, sizeof(info) - 1, out, 32);
}

bool s5_read_own_payload(std::vector<unsigned char>* ciphertext, unsigned char nonce[12],
                         unsigned char tag[16]) {
    ciphertext->clear();
    HMODULE module = nullptr;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                           | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCSTR>(&s5_read_own_payload), &module) == 0
            || module == nullptr) {
        return false;
    }
    char path[MAX_PATH * 4] = {};
    if (GetModuleFileNameA(module, path, sizeof(path)) == 0) return false;
    HANDLE file = CreateFileA(path, GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size;
    bool ok = GetFileSizeEx(file, &size) != 0
            && size.QuadPart >= static_cast<LONGLONG>(kS5PayloadFooterSize);
    unsigned char footer[kS5PayloadFooterSize];
    if (ok) {
        LARGE_INTEGER offset;
        offset.QuadPart = size.QuadPart - static_cast<LONGLONG>(kS5PayloadFooterSize);
        ok = SetFilePointerEx(file, offset, nullptr, FILE_BEGIN) != 0
                && ReadFile(file, footer, sizeof(footer), nullptr, nullptr) != 0;
    }
    if (ok) {
        std::memcpy(nonce, footer, 12);
        std::memcpy(tag, footer + 12, 16);
        ok = std::memcmp(footer + 28, "CHPY", 4) == 0;
        uint32_t version = 0;
        uint64_t payload_len = 0;
        std::memcpy(&version, footer + 32, 4);
        std::memcpy(&payload_len, footer + 36, 8);
        ok = ok && version == 1 && payload_len > 0
                && payload_len <= static_cast<uint64_t>(size.QuadPart) - kS5PayloadFooterSize;
        if (ok) {
            LARGE_INTEGER offset;
            offset.QuadPart = size.QuadPart - static_cast<LONGLONG>(kS5PayloadFooterSize)
                    - static_cast<LONGLONG>(payload_len);
            ok = SetFilePointerEx(file, offset, nullptr, FILE_BEGIN) != 0;
            ciphertext->resize(static_cast<size_t>(payload_len));
            ok = ok && ReadFile(file, ciphertext->data(), static_cast<DWORD>(payload_len),
                                nullptr, nullptr) != 0;
        }
    }
    CloseHandle(file);
    if (!ok) ciphertext->clear();
    return ok;
}

bool s5_payload_info(std::vector<unsigned char>* ciphertext, unsigned char nonce[12],
                     unsigned char tag[16]) {
    return s5_read_own_payload(ciphertext, nonce, tag);
}

bool s5_derive_hidden_payload_key(const HandleSlot& slot, unsigned char out[32]) {
    SlotKey resource_key(slot);
    if (!resource_key.ok) return false;
    const unsigned char salt[] = "chimera/hidden-blob-salt/v1";
    const unsigned char info[] = "chimera/hidden-blob/v1";
    return hkdf_sha256(resource_key.data(), 32, salt, sizeof(salt) - 1,
                       info, sizeof(info) - 1, out, 32);
}

bool s5_unpack_hidden_blob(const HandleSlot& slot, const unsigned char* blob, size_t blob_len,
                           const unsigned char expected[32], std::vector<unsigned char>& out) {
    out.clear();
    if (blob == nullptr || blob_len < 28 || expected == nullptr) return false;
    unsigned char key[32];
    if (!s5_derive_hidden_payload_key(slot, key)) return false;
    const size_t plain_capacity = blob_len - 28;
    std::vector<unsigned char> plain(plain_capacity);
    size_t plain_len = 0;
    const bool decrypted = aes_gcm_decrypt(key, blob, 12, blob + 12, plain_capacity,
                                           blob + blob_len - 16, 16, nullptr, 0,
                                           plain.data(), &plain_len);
    secure_wipe(key, sizeof(key));
    if (!decrypted || plain_len == 0 || plain_len > plain_capacity) {
        secure_wipe(plain.data(), plain.size());
        return false;
    }
    unsigned char digest[32];
    SHA256(plain.data(), plain_len, digest);
    const bool matches = CRYPTO_memcmp(digest, expected, 32) == 0;
    secure_wipe(digest, sizeof(digest));
    if (!matches) {
        secure_wipe(plain.data(), plain.size());
        return false;
    }
    plain.resize(plain_len);
    out.swap(plain);
    return true;
}

}  // namespace
// B3-1: forward declarations needed to record the JNI entry prologues in the integrity watch list.
extern "C" JNIEXPORT jlong JNICALL
Java_dev_chimera_runtime_ChimeraRuntime_nativeCheckHandle(JNIEnv*, jclass, jlong);
extern "C" JNIEXPORT jbyteArray JNICALL
Java_dev_chimera_runtime_ChimeraRuntime_nativeCompute(JNIEnv*, jclass, jlong, jbyteArray);
extern "C" JNIEXPORT jint JNICALL
Java_dev_chimera_runtime_ChimeraRuntime_nativeHiddenClassBytesMatch(
        JNIEnv*, jclass, jclass, jbyteArray);

// ------------------------------------------------------------------ B3-1 code section integrity
//
// KI-03: the native module self-checks its own executable section. JNI_OnLoad snapshots a SHA-256
// baseline of the PE ".text" section and the first 5 bytes of the protected functions; the hot JNI
// entries re-hash at most every kIntegrityCheckIntervalMs and poison their results when the section
// changed or a protected prologue starts with INT3 (0xCC) / JMP rel32 (0xE9). Queries never throw.

constexpr uint64_t kIntegrityCheckIntervalMs = 250;
// Capacity bug (found 2026-10-22): init_code_integrity() registers 14 functions and JNI_OnLoad
// adds 3 more (is_virtual_machine, nativeIsVirtualMachine, nativeDeriveClassKey). With the old
// limit of 14 watch_function() silently dropped those three - the "P2-4" comment below claimed the
// VM verdict was watched while it was not. The limit is now comfortably above the real count and
// watch_function reports overflow instead of dropping entries silently.
constexpr size_t kMaxWatchedFunctions = 24;
// Hardware-breakpoint scan: bounded thread count and a slow cadence. Suspending every thread on
// every integrity tick would be both slow and deadlock-prone.
// Measured on the real client: the JVM runs ~500 threads, and a full suspend/read/resume sweep
// costs ~600ms. At 5s cadence that alone added 9s to startup; 30s costs ~0.2s total and still
// catches a breakpoint armed before launch on the very first sweep.
constexpr int kMaxThreadsScanned = 96;
constexpr uint64_t kDrScanIntervalMs = 30000;
// Red team round 3: the synchronous scan skipped the thread it ran on - which is the thread doing
// the decrypting - and cached its result for 30s, so a breakpoint armed on that thread stayed
// invisible for the whole window. A dedicated native watchdog thread scans everything (its own
// thread is the only one it can skip) on a short cadence, off the startup critical path. 5s is
// affordable now precisely because nothing waits for it.
constexpr uint64_t kDrWatchdogIntervalMs = 5000;
// Written only by the watchdog, read by every integrity check. Sticky: one hit condemns the process.
volatile LONG g_dr_armed = 0;
volatile LONG g_dr_watchdog_started = 0;

struct WatchedFunction {
    const char* name;
    const void* address;
    unsigned char head[5];
};

WatchedFunction g_watched[kMaxWatchedFunctions];
size_t g_watched_count = 0;
const unsigned char* g_text_start = nullptr;
size_t g_text_size = 0;
unsigned char g_text_sha256[32];
bool g_baseline_ready = false;
uint64_t g_last_check_ms = 0;
bool g_last_check_ok = false;

void invalidate_integrity_cache() {
    g_last_check_ms = 0;
    g_last_check_ok = false;
}

void watch_function(const char* name, const void* address) {
    if (address == nullptr) return;
    if (g_watched_count >= kMaxWatchedFunctions) {
        // Never silently drop a watched function: a full table means the guard silently stops
        // covering the newest (usually most security-relevant) entries.
        std::fprintf(stderr, "[chimera-native] watch table full, not watching %s\n",
                name != nullptr ? name : "?");
        return;
    }
    WatchedFunction& entry = g_watched[g_watched_count++];
    entry.name = name;
    entry.address = address;
    std::memcpy(entry.head, address, sizeof(entry.head));
}

bool locate_text_section() {
    HMODULE module = nullptr;
    const DWORD flags = static_cast<DWORD>(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
            | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT);
    if (GetModuleHandleExA(flags, reinterpret_cast<LPCSTR>(&locate_text_section), &module) == 0
            || module == nullptr) {
        return false;
    }
    const auto* base = reinterpret_cast<const unsigned char*>(module);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
        const bool named_text = std::memcmp(section->Name, ".text", 5) == 0;
        const bool executable = (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
                && (section->Characteristics & IMAGE_SCN_CNT_CODE) != 0;
        if (!named_text && !executable) continue;
        const size_t size = section->Misc.VirtualSize > 0
                ? section->Misc.VirtualSize : section->SizeOfRawData;
        if (size == 0) continue;
        g_text_start = base + section->VirtualAddress;
        g_text_size = size;
        return true;
    }
    return false;
}

// INT3 (0xCC) / JMP rel32 (0xE9) inline hooks change the prologue; any other prologue change is
// also a failure and is caught by the SHA-256 comparison below.
bool protected_prologue_patched() {
    for (size_t i = 0; i < g_watched_count; i++) {
        const auto* current = reinterpret_cast<const unsigned char*>(g_watched[i].address);
        if (std::memcmp(current, g_watched[i].head, sizeof(g_watched[i].head)) != 0) {
            return true;
        }
    }
    return false;
}

/**
 * True when any thread of this process has a hardware breakpoint armed (DR0..DR3 != 0).
 *
 * <p>Why this is needed: {@link protected_prologue_patched} compares the first five bytes of each
 * watched function. A hardware breakpoint changes <b>no byte at all</b> - the CPU raises the trap -
 * so the entire watch list is blind to the most common way of intercepting a native function. This
 * closes that channel.</p>
 *
 * <p>Cost and safety: the scan suspends each foreign thread just long enough to read its context
 * and resumes it immediately, allocates nothing in between, and runs at most once every
 * {@code kDrScanIntervalMs}. Failures (cannot open / suspend) are treated as "no signal" - the
 * check must never destabilise a legitimate launch.</p>
 */
/**
 * One full sweep: suspend, read DR0..DR3, resume.
 *
 * <p>Skips only the calling thread - a thread cannot read its own context without suspending
 * itself. That is exactly why the sweep must not run on the thread being watched: the old
 * synchronous version ran on the decrypting thread and therefore never looked at it. Running the
 * sweep from the watchdog makes the skipped thread the watchdog itself, i.e. the one thread an
 * attacker has no reason to instrument.</p>
 *
 * <p>Allocates nothing between suspend and resume, so a thread parked inside the process heap
 * cannot deadlock against the scan.</p>
 */
bool dr_scan_all_threads() {
    const DWORD self_pid = GetCurrentProcessId();
    const DWORD self_tid = GetCurrentThreadId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }
    bool armed = false;
    THREADENTRY32 entry;
    entry.dwSize = sizeof(entry);
    int scanned = 0;
    if (Thread32First(snapshot, &entry)) {
        do {
            if (entry.th32OwnerProcessID != self_pid || entry.th32ThreadID == self_tid) continue;
            if (++scanned > kMaxThreadsScanned) break;
            HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT,
                    FALSE, entry.th32ThreadID);
            if (thread == nullptr) continue;
            if (SuspendThread(thread) != static_cast<DWORD>(-1)) {
                CONTEXT context;
                std::memset(&context, 0, sizeof(context));
                context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                if (GetThreadContext(thread, &context) != 0
                        && (context.Dr0 != 0 || context.Dr1 != 0
                            || context.Dr2 != 0 || context.Dr3 != 0)) {
                    armed = true;
                }
                ResumeThread(thread);
            }
            CloseHandle(thread);
        } while (!armed && Thread32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return armed;
}

/** Sweeps until it finds a breakpoint, then condemns the process for good and exits. */
DWORD WINAPI dr_watchdog_proc(LPVOID) {
    for (;;) {
        if (dr_scan_all_threads()) {
            InterlockedExchange(&g_dr_armed, 1);
            return 0;
        }
        Sleep(static_cast<DWORD>(kDrWatchdogIntervalMs));
    }
}

/**
 * Starts the watchdog once. Called from {@code JNI_OnLoad}, before any class is decrypted.
 *
 * <p>Test mode never starts it: the sweep suspends foreign threads and the unit suite runs dozens
 * of them inside one JVM.</p>
 */
void start_dr_watchdog() {
    if (g_test_mode) return;
    if (InterlockedCompareExchange(&g_dr_watchdog_started, 1, 0) != 0) return;
    HANDLE thread = CreateThread(nullptr, 0, dr_watchdog_proc, nullptr, 0, nullptr);
    if (thread == nullptr) {
        // No watchdog: fall back to the old synchronous sweep rather than lose the signal.
        InterlockedExchange(&g_dr_watchdog_started, 0);
        return;
    }
    CloseHandle(thread);
}

bool debug_registers_armed() {
    if (g_dr_armed != 0) return true;
    if (g_dr_watchdog_started != 0) return false;  // the watchdog is the authority
    // Fallback path only (CreateThread failed): self-skipping and rate-limited, but at least the
    // other threads still get looked at.
    static uint64_t last_scan_ms = 0;
    static bool last_result = false;
    const uint64_t now = GetTickCount64();
    if (last_scan_ms != 0 && now >= last_scan_ms && now - last_scan_ms < kDrScanIntervalMs) {
        return last_result;
    }
    last_scan_ms = now;
    last_result = dr_scan_all_threads();
    return last_result;
}

bool code_section_intact_fresh() {
    if (g_test_mode) return true;  // CHIMERA_TEST_MODE: delayed/skipped B3-1 baseline
    if (!g_baseline_ready || g_text_start == nullptr || g_text_size == 0) return false;
    // Hardware breakpoints change no byte, so the prologue snapshot below cannot see them.
    if (debug_registers_armed()) return false;
    if (protected_prologue_patched()) return false;
    unsigned char current[32];
    SHA256(g_text_start, g_text_size, current);
    return std::memcmp(current, g_text_sha256, sizeof(current)) == 0;
}

bool code_section_intact() {
    if (s5_anti_dump_should_poison()) return false;  // release anti-dump gate (dev: telemetry only)
    if (!g_baseline_ready) return false;
    const uint64_t now = GetTickCount64();
    if (g_last_check_ms != 0 && now >= g_last_check_ms
            && now - g_last_check_ms < kIntegrityCheckIntervalMs) {
        return g_last_check_ok;
    }
    const bool ok = code_section_intact_fresh();
    g_last_check_ms = now;
    g_last_check_ok = ok;
    return ok;
}

void init_code_integrity() {
    g_watched_count = 0;
    watch_function("compute_locked", reinterpret_cast<const void*>(&compute_locked));
    watch_function("find_handle_locked", reinterpret_cast<const void*>(&find_handle_locked));
    watch_function("poison_key", reinterpret_cast<const void*>(&poison_key));
    watch_function("ed25519_verify", reinterpret_cast<const void*>(&ed25519_verify));
    watch_function("x25519_shared", reinterpret_cast<const void*>(&x25519_shared));
    watch_function("aes_gcm_decrypt", reinterpret_cast<const void*>(&aes_gcm_decrypt));
    watch_function("hkdf_sha256", reinterpret_cast<const void*>(&hkdf_sha256));
    watch_function("nativeCheckHandle",
            reinterpret_cast<const void*>(&Java_dev_chimera_runtime_ChimeraRuntime_nativeCheckHandle));
    watch_function("nativeCompute",
            reinterpret_cast<const void*>(&Java_dev_chimera_runtime_ChimeraRuntime_nativeCompute));
    watch_function("compute_b7_decision_program",
            reinterpret_cast<const void*>(&compute_b7_decision_program));
    watch_function("ed25519_verify_bn", reinterpret_cast<const void*>(&ed25519_verify_bn));
    watch_function("s5_anti_dump_scan", reinterpret_cast<const void*>(&s5_anti_dump_scan));
    watch_function("hidden_class_method_hash_any",
            reinterpret_cast<const void*>(&hidden_class_method_hash_any));
    watch_function("nativeHiddenClassBytesMatch",
            reinterpret_cast<const void*>(&Java_dev_chimera_runtime_ChimeraRuntime_nativeHiddenClassBytesMatch));
    if (!locate_text_section()) {
        g_baseline_ready = false;
        invalidate_integrity_cache();
        return;
    }
    SHA256(g_text_start, g_text_size, g_text_sha256);
    g_baseline_ready = true;
    invalidate_integrity_cache();
}

extern "C" {

// ------------------------------------------------------------------ build-pinned auth pubkey
//
// SECURITY (2026-10-22): g_server_pub used to come straight from the caller, and the caller reads
// it out of chimera/auth.dat — a plain text resource inside the jar that no integrity check
// covers. Editing two lines (server=, pubkey=) pointed the client at an attacker-run server whose
// responses it would happily verify. The public key is now a compile-time constant, so the only
// way to change it is to rebuild the VMP'd DLL.
#ifndef CHIMERA_PINNED_AUTH_PUBKEY_HEX
#define CHIMERA_PINNED_AUTH_PUBKEY_HEX ""
#endif

// P1-3: SHA-256 of the same 32 bytes, computed by the build script from that very hex. Kept as a
// separate constant so the runtime can re-hash the pinned key and detect a patched .rdata string.
#ifndef CHIMERA_PINNED_AUTH_PUBKEY_FP_HEX
#define CHIMERA_PINNED_AUTH_PUBKEY_FP_HEX ""
#endif

// P2-1: licence-server URL baked at build time. Empty means "read it from auth.dat" (dev builds).
#ifndef CHIMERA_PINNED_AUTH_SERVER
#define CHIMERA_PINNED_AUTH_SERVER ""
#endif

namespace {
int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
}  // namespace

/** Decodes the build-pinned public key; false when the build did not pin one (dev builds). */
static bool pinned_auth_pubkey(unsigned char out[32]) {
    static const char* hex = CHIMERA_PINNED_AUTH_PUBKEY_HEX;
    static const size_t len = std::strlen(hex);
    if (len != 64) return false;
    for (int i = 0; i < 32; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<unsigned char>((hi << 4) | lo);
    }
    return true;
}

/** Records that the artifact tried to override the pinned key (diagnostic + tamper signal). */
static void note_auth_pub_tamper() {
    const char* home = getenv("USERPROFILE");
    if (home == nullptr) return;
    char path[MAX_PATH * 2];
    std::snprintf(path, sizeof(path), "%s\\.chimera\\gate-diag.log", home);
    FILE* file = nullptr;
    if (fopen_s(&file, path, "a") != 0 || file == nullptr) return;
    std::fprintf(file, "SECURITY: auth.dat pubkey != build-pinned key (ignored, pinned key used)\n");
    fclose(file);
}

/**
 * True when this process is running inside a virtual machine.
 *
 * <p>Deliberately does NOT trust the CPUID hypervisor bit: Windows 11 enables VBS/Hyper-V by
 * default, which sets that bit on ordinary end-user machines. Using it alone would empty the mod
 * for a large share of legitimate players. Instead the vendor string must name an actual hypervisor
 * product, or a vendor-specific driver/service must be present.</p>
 *
 * <p>{@code Microsoft Hv} is intentionally excluded - that is Hyper-V, including VBS on a normal
 * desktop.</p>
 *
 * <p>Virtualized by VMProtect (CHIMERA_VMP_BEGIN/END). The body is written with a single exit point
 * on purpose: a marker pair cannot be wrapped around a function with early returns without either
 * leaking the END marker or leaving part of the logic in plain machine code. noinline keeps -O2
 * from folding the body into a caller and dropping the markers with it.</p>
 */
#if defined(_MSC_VER)
__declspec(noinline)
#else
__attribute__((noinline))
#endif
static bool is_virtual_machine() {
    CHIMERA_VMP_BEGIN("chimera.vm.detect");
    bool vm = false;
    int regs[4] = {0, 0, 0, 0};
#if defined(_MSC_VER)
    __cpuid(regs, 0x40000000);
#else
    __get_cpuid(0x40000000, (unsigned*) &regs[0], (unsigned*) &regs[1],
            (unsigned*) &regs[2], (unsigned*) &regs[3]);
#endif
    char vendor[13] = {0};
    std::memcpy(vendor + 0, &regs[1], 4);
    std::memcpy(vendor + 4, &regs[2], 4);
    std::memcpy(vendor + 8, &regs[3], 4);
    if (std::strcmp(vendor, "VMwareVMware") == 0
            || std::strcmp(vendor, "VBoxVBoxVBox") == 0
            || std::strcmp(vendor, "KVMKVMKVM") == 0
            || std::strcmp(vendor, "XenVMMXenVMM") == 0
            || std::strcmp(vendor, "TCGTCGTCGTCG") == 0) {
        vm = true;
    }
    // Guest-only artefacts. Deliberately excludes vmci / vmhgfs / vmmouse / vmusbmouse and the
    // "vmci" service: VMware Workstation installs those on the HOST too, so checking them flagged
    // every developer machine that merely has Workstation installed (measured: a real host was
    // emptied by the VM rule). Only guest additions are trustworthy here.
    static const char* kGuestDrivers[] = {
            "C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
            "C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
            "C:\\Windows\\System32\\drivers\\VBoxSF.sys",
    };
    for (size_t i = 0; i < sizeof(kGuestDrivers) / sizeof(kGuestDrivers[0]) && !vm; i++) {
        if (GetFileAttributesA(kGuestDrivers[i]) != INVALID_FILE_ATTRIBUTES) {
            vm = true;
        }
    }
    // VMware Tools registers "VMTools" inside the guest only (Workstation on a host does not).
    static const char* kGuestServices[] = {"VMTools", "VBoxGuest", "VBoxService"};
    for (size_t i = 0; i < sizeof(kGuestServices) / sizeof(kGuestServices[0]) && !vm; i++) {
        char subkey[256];
        std::snprintf(subkey, sizeof(subkey),
                "SYSTEM\\CurrentControlSet\\Services\\%s", kGuestServices[i]);
        HKEY key = nullptr;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subkey, 0, KEY_QUERY_VALUE, &key) == ERROR_SUCCESS) {
            RegCloseKey(key);
            vm = true;
        }
    }
    CHIMERA_VMP_END();
    return vm;
}

/** JNI: VM check for the runtime. Native so a patched jar cannot answer "not a VM". */
JNIEXPORT jboolean JNICALL
Java_dev_chimera_runtime_ChimeraRuntime_nativeIsVirtualMachine(JNIEnv*, jclass) {
    static const int cached = is_virtual_machine() ? 1 : 0;
    return cached != 0 ? JNI_TRUE : JNI_FALSE;
}

/** True when this DLL carries a build-pinned auth key (tests cannot mint responses for it). */
JNIEXPORT jboolean JNICALL
Java_dev_chimera_runtime_ChimeraRuntime_nativeAuthPubkeyPinned(JNIEnv*, jclass) {
    unsigned char pinned[32];
    return pinned_auth_pubkey(pinned) ? JNI_TRUE : JNI_FALSE;
}

/**
 * The licence server baked into this build, or an empty string when the build pinned none.
 *
 * <p>P2-1: {@code auth.dat}'s {@code server=} line was still honoured, so an attacker could point
 * the client at their own endpoint (DoS, or a proxy that observes tokens - signatures cannot be
 * forged, but traffic can be watched). When a server is baked in, the runtime uses it and ignores
 * the file.</p>
 */
JNIEXPORT jstring JNICALL
Java_dev_chimera_runtime_ChimeraRuntime_nativePinnedAuthServer(JNIEnv* env, jclass) {
    static const char* pinned = CHIMERA_PINNED_AUTH_SERVER;
    return env->NewStringUTF(pinned);
}

// ------------------------------------------------------------------------- #18 device hints
//
// Best-effort QQ number, consumed by the per-licence watermark (#19). Three hard rules:
//   * READ-ONLY. Only the on-disk "Tencent Files" directory tree and HKCU\Software\Tencent are
//     inspected. Process memory is never scanned: that is exactly the behaviour AV engines classify
//     as a credential stealer, and it is unnecessary - the account directory name is the QQ number.
//   * EMPTY ON FAILURE. Unknown stays unknown: no prompt, no guess, no derived value.
//   * BOUNDED. Fixed directory depth and a hard cap on registry nodes so a pathological machine
//     cannot stall startup.

static bool all_digits(const char* text, size_t length, size_t min_length, size_t max_length) {
    if (text == nullptr || length < min_length || length > max_length) return false;
    for (size_t i = 0; i < length; i++) {
        if (text[i] < '0' || text[i] > '9') return false;
    }
    return true;
}

/** Newest all-digit subdirectory of {@code base} (QQ keeps one directory per account). */
static bool qq_from_directory(const char* base, char out[16]) {
    char pattern[MAX_PATH];
    if (std::snprintf(pattern, sizeof(pattern), "%s\\*", base) <= 0) return false;
    WIN32_FIND_DATAA data;
    HANDLE find = FindFirstFileA(pattern, &data);
    if (find == INVALID_HANDLE_VALUE) return false;
    bool found = false;
    FILETIME newest = {0, 0};
    do {
        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) continue;
        const size_t len = std::strlen(data.cFileName);
        if (!all_digits(data.cFileName, len, 5, 11)) continue;
        if (found && CompareFileTime(&data.ftLastWriteTime, &newest) <= 0) continue;
        std::memcpy(out, data.cFileName, len);
        out[len] = '\0';
        newest = data.ftLastWriteTime;
        found = true;
    } while (FindNextFileA(find, &data));
    FindClose(find);
    return found;
}

/**
 * Walks one registry subtree looking for an all-digit key name or string value.
 *
 * <p>QQ stores its per-version state under {@code HKCU\Software\Tencent\<product>}; the account
 * number appears as a subkey name in some versions and as a value in others, so both are checked.
 * Enumeration is capped by {@code *budget} so a machine with a huge Tencent tree costs nothing.</p>
 */
static bool qq_from_key(HKEY root, const char* path, int depth, int* budget, char out[16]) {
    if (depth <= 0 || *budget <= 0) return false;
    HKEY key = nullptr;
    if (RegOpenKeyExA(root, path, 0, KEY_READ, &key) != ERROR_SUCCESS) return false;
    --(*budget);
    bool found = false;
    char name[256];
    for (DWORD index = 0; index < 32 && !found && *budget > 0; index++) {
        DWORD name_len = sizeof(name) - 1;
        const LONG rc = RegEnumKeyExA(key, index, name, &name_len, nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) continue;
        name[name_len] = '\0';
        if (all_digits(name, name_len, 5, 11)) {
            std::memcpy(out, name, name_len);
            out[name_len] = '\0';
            found = true;
            break;
        }
        char child[512];
        if (std::snprintf(child, sizeof(child), "%s\\%s", path, name) > 0
                && qq_from_key(root, child, depth - 1, budget, out)) {
            found = true;
        }
    }
    // Values: some builds keep the last account as a plain string.
    for (DWORD index = 0; index < 32 && !found && *budget > 0; index++) {
        char value_name[256];
        DWORD value_len = sizeof(value_name) - 1;
        DWORD type = 0;
        char data[64];
        DWORD data_len = sizeof(data) - 1;
        const LONG rc = RegEnumValueA(key, index, value_name, &value_len, nullptr, &type,
                reinterpret_cast<LPBYTE>(data), &data_len);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) continue;
        if (data_len == 0 || data_len >= sizeof(data)) continue;
        data[data_len] = '\0';
        if (all_digits(data, std::strlen(data), 5, 11)) {
            std::snprintf(out, 16, "%s", data);
            found = true;
        }
    }
    RegCloseKey(key);
    return found;
}

static bool qq_from_registry(char out[16]) {
    int budget = 128;
    // H: HKCU only. Walking HKLM\WOW6432Node\Tencent as well reads like an installer probe and
    // buys nothing - a per-user QQ install keeps its account under HKCU. Fewer roots, smaller
    // footprint, same answer.
    return qq_from_key(HKEY_CURRENT_USER, "Software\\Tencent", 3, &budget, out);
}

/** #18: the QQ number this machine appears to be logged in with, or "" when unknown. */
JNIEXPORT jstring JNICALL
Java_dev_chimera_runtime_ChimeraRuntime_nativeQqHint(JNIEnv* env, jclass) {
    char qq[16] = {0};
    bool found = false;
    char home[MAX_PATH];
    const DWORD home_len = GetEnvironmentVariableA("USERPROFILE", home, sizeof(home));
    if (home_len > 0 && home_len < sizeof(home)) {
        char dir[MAX_PATH];
        // OneDrive-redirected Documents is the default on many Windows 11 installs, so both
        // locations are probed. A profile without QQ simply misses both.
        static const char* kSuffixes[] = {
                "\\Documents\\Tencent Files",
                "\\OneDrive\\Documents\\Tencent Files",
        };
        for (const char* suffix : kSuffixes) {
            if (std::snprintf(dir, sizeof(dir), "%s%s", home, suffix) <= 0) continue;
            if (qq_from_directory(dir, qq)) {
                found = true;
                break;
            }
        }
    }
    if (!found) {
        found = qq_from_registry(qq);
    }
    return env->NewStringUTF(found ? qq : "");
}

// ---------------------------------------------------------------- #19 watermark public key
//
// The operator's RSA public key (X.509/SPKI, Base64), baked at build time. The per-licence
// watermark payload is sealed with it, so only the licence server (holder of the private key) can
// read which licence a leaked build was activated with. Baking it into the protected DLL means the
// client cannot swap in its own key without patching virtualized code.
#ifndef CHIMERA_WM_PUBKEY_B64
#define CHIMERA_WM_PUBKEY_B64 ""
#endif

/** #19: baked watermark public key, or "" when the build pinned none (watermarking disabled). */
JNIEXPORT jstring JNICALL
Java_dev_chimera_runtime_ChimeraRuntime_nativeWatermarkKey(JNIEnv* env, jclass) {
    static const char* key = CHIMERA_WM_PUBKEY_B64;
    return env->NewStringUTF(key);
}

// ------------------------------------------------------------ build-pinned manifest HMAC key
//
// SECURITY (#9, audit 2026-10-22): chimera/manifest.dat lists every chimera/** resource, but a
// manifest that the artifact can authenticate by itself protects nothing: the sealed manifest.mac
// is derived from build material (kek/envSalt) that anyone rebuilding the jar can reproduce, so an
// attacker who edits auth.dat/env.dat/strings.dat simply re-seals the manifest. The HMAC key below
// is a compile-time constant of this (VMProtect-protected) DLL, so verifying the manifest requires
// the shipped native image and the jar cannot mint a new tag.
//
// Deliberately lock-free and handle-free: it must be callable before any authorization state
// exists, because it is what protects the very resources (auth.dat) the gate consumes.
#ifndef CHIMERA_MANIFEST_KEY_HEX
#define CHIMERA_MANIFEST_KEY_HEX ""
#endif

/** Decodes the build-pinned manifest key; false when the build did not pin one. */
static bool pinned_manifest_key(unsigned char out[32]) {
    static const char* hex = CHIMERA_MANIFEST_KEY_HEX;
    static const size_t len = std::strlen(hex);
    if (len != 64) return false;
    for (int i = 0; i < 32; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<unsigned char>((hi << 4) | lo);
    }
    return true;
}

/** 1 when this DLL authenticates the manifest (i.e. it was built with -DCHIMERA_MANIFEST_KEY_HEX). */
JNIEXPORT jboolean JNICALL
Java_dev_chimera_runtime_ChimeraRuntime_nativeManifestKeyPinned(JNIEnv*, jclass) {
    unsigned char key[32];
    const bool ok = pinned_manifest_key(key);
    secure_wipe(key, sizeof(key));
    return ok ? JNI_TRUE : JNI_FALSE;
}

/**
 * HMAC-SHA256(manifest) under the build-pinned key, compared in constant time against {@code mac}.
 * Returns JNI_FALSE on every failure (no pinned key, wrong length, OpenSSL error), so a caller that
 * checks the boolean fails closed. No handle, no lock, no authorization state: safe to call first.
 */
JNIEXPORT jboolean JNICALL Java_dev_chimera_runtime_ChimeraRuntime_nativeVerifyManifest(
        JNIEnv* env, jclass, jbyteArray manifest, jbyteArray mac) {
    unsigned char key[32];
    if (!pinned_manifest_key(key)) return JNI_FALSE;
    auto body = jbyte_array(env, manifest);
    auto tag = jbyte_array(env, mac);
    bool ok = false;
    if (!body.empty() && tag.size() == 32) {
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digest_len = 0;
        std::memset(digest, 0, sizeof(digest));
        if (HMAC(EVP_sha256(), key, 32, body.data(), body.size(), digest, &digest_len) != nullptr
                && digest_len == 32) {
            unsigned int diff = 0;
            for (size_t i = 0; i < 32; i++) diff |= digest[i] ^ tag[i];
            ok = (diff == 0);
        }
        secure_wipe(digest, sizeof(digest));
    }
    secure_wipe(key, sizeof(key));
    return ok ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL Java_dev_chimera_runtime_ChimeraRuntime_nativeSetAuthContext(
        JNIEnv* env, jclass, jbyteArray pubkey, jbyteArray account) {
    ensure_lock();
    LockGuard guard;
    auto pub = jbyte_array(env, pubkey);
    auto acc = jbyte_array(env, account);
    if (pub.size() == 32) {
        // The build-pinned key always wins: auth.dat is editable and has no integrity coverage.
        unsigned char pinned[32];
        if (pinned_auth_pubkey(pinned)) {
            if (std::memcmp(pinned, pub.data(), 32) != 0) {
                note_auth_pub_tamper();
            }
            std::memcpy(g_server_pub, pinned, 32);
        } else {
            std::memcpy(g_server_pub, pub.data(), 32);
        }
        g_have_server_pub = true;
        if (g_pinned_ed_pub != nullptr) EVP_PKEY_free(g_pinned_ed_pub);
        g_pinned_ed_pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, g_server_pub, 32);
        for (size_t i = 0; i < kPkeyCtxPoolSize; i++) {
            if (g_verify_pkey_ctx_pool[i] != nullptr) EVP_PKEY_CTX_free(g_verify_pkey_ctx_pool[i]);
            g_verify_pkey_ctx_pool[i] = g_pinned_ed_pub != nullptr
                    ? EVP_PKEY_CTX_new(g_pinned_ed_pub, nullptr) : nullptr;
            InterlockedExchange(&g_verify_pkey_ctx_busy[i], 0);
        }
        g_pkey_ctx_pool_ready = g_pinned_ed_pub != nullptr;
        for (size_t i = 0; i < kPkeyCtxPoolSize; i++) {
            if (g_verify_pkey_ctx_pool[i] == nullptr) g_pkey_ctx_pool_ready = false;
        }
    }
    g_account_len = acc.size() > sizeof(g_account) ? sizeof(g_account) : acc.size();
    if (g_account_len > 0) std::memcpy(g_account, acc.data(), g_account_len);
}

JNIEXPORT jbyteArray JNICALL Java_dev_chimera_runtime_ChimeraRuntime_nativeCreateClientKey(
        JNIEnv* env, jclass) {
    ensure_lock();
    LockGuard guard;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    std::vector<unsigned char> pub(32, 0);
    if (ctx == nullptr) {
        return make_byte_array(env, poison_key(nullptr, 0));
    }
    EVP_PKEY* key = nullptr;
    bool ok = EVP_PKEY_keygen_init(ctx) == 1 && EVP_PKEY_keygen(ctx, &key) == 1;
    if (ok) {
        size_t priv_len = 32;
        size_t pub_len = 32;
        ok = EVP_PKEY_get_raw_private_key(key, g_client_priv, &priv_len) == 1
                && priv_len == 32
                && EVP_PKEY_get_raw_public_key(key, pub.data(), &pub_len) == 1
                && pub_len == 32;
        if (ok) g_have_client_priv = true;
    }
    if (key) EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    if (!ok) return make_byte_array(env, poison_key(nullptr, 0));
    return make_byte_array(env, pub);
}

JNIEXPORT jlong JNICALL Java_dev_chimera_runtime_ChimeraRuntime_nativeVerifyAuth(
        JNIEnv* env, jclass, jbyteArray response, jbyteArray hwid) {
    ensure_lock();
    LockGuard guard;

    auto hwid_bytes = jbyte_array(env, hwid);
    auto response_bytes = jbyte_array(env, response);
    std::string json(response_bytes.begin(), response_bytes.end());

    // B3-1: a patched native module must not run crypto or hand out a usable-looking session.
    if (!code_section_intact()) {
        return auth_poison_result(hwid_bytes);
    }

    // 1. anti-debug / anti-frida: no crypto at all, formatted poison key.
    if (should_poison()) {
        return auth_poison_result(hwid_bytes);
    }
    if (!g_have_client_priv || !g_have_server_pub) {
        return auth_poison_result(hwid_bytes);
    }

    // 2. parse the signed response.
    std::string nonce_b64, ephemeral_b64, wrapped_b64, token, signature_b64, account;
    long long expires_at = 0, issued_at = 0, sequence = 0;
    if (!find_string(json, "server_nonce", nonce_b64)
            || !find_string(json, "server_ephemeral_pub", ephemeral_b64)
            || !find_string(json, "wrapped_ck", wrapped_b64)
            || !find_string(json, "token", token)
            || !find_string(json, "signature", signature_b64)
            || !find_string(json, "account", account)
            || !find_long(json, "expires_at", expires_at)
            || !find_long(json, "issued_at", issued_at)
            || !find_long(json, "sequence", sequence)) {
        return auth_poison_result(hwid_bytes);
    }

    std::vector<unsigned char> signature, nonce, ephemeral, wrapped;
    if (!b64_decode(signature_b64, signature) || signature.size() != 64
            || !b64_decode(nonce_b64, nonce) || nonce.size() != 16
            || !b64_decode(ephemeral_b64, ephemeral) || ephemeral.size() != 32
            || !b64_decode(wrapped_b64, wrapped) || wrapped.size() != 60) {
        return auth_poison_result(hwid_bytes);
    }

    // 3. canonical transcript (must stay byte-identical to Java/server).
    std::string canonical = "{\"expires_at\":" + std::to_string(expires_at)
            + ",\"issued_at\":" + std::to_string(issued_at)
            + ",\"sequence\":" + std::to_string(sequence)
            + ",\"server_ephemeral_pub\":\"" + ephemeral_b64
            + "\",\"server_nonce\":\"" + nonce_b64
            + "\",\"token\":\"" + token
            + "\",\"wrapped_ck\":\"" + wrapped_b64 + "\"}";

    // 4. B7: reserve a PENDING handle, then CALL_NATIVE(VERIFY_ED25519) through the opaque table.
    //    The raw verify result is stored on the handle, never returned to Java.
    unsigned char verify_seed_key[32];
    unsigned char verify_seed_nonce[16];
    if (RAND_bytes(verify_seed_key, 32) != 1 || RAND_bytes(verify_seed_nonce, 16) != 1) {
        return auth_poison_result(hwid_bytes);
    }
    HandleSlot* slot = store_handle_slot_locked(verify_seed_key, verify_seed_nonce, kHandlePending);
    if (canonical.size() > sizeof(slot->transcript) || signature.size() != 64) {
        secure_wipe(verify_seed_key, sizeof(verify_seed_key));
        secure_wipe(verify_seed_nonce, sizeof(verify_seed_nonce));
        wipe_slot_locked(*slot);
        return auth_poison_result(hwid_bytes);
    }
    std::memcpy(slot->transcript, canonical.data(), canonical.size());
    slot->transcript_len = static_cast<uint16_t>(canonical.size());
    std::memcpy(slot->signature, signature.data(), 64);
    secure_wipe(verify_seed_key, sizeof(verify_seed_key));
    secure_wipe(verify_seed_nonce, sizeof(verify_seed_nonce));
    NativeArg verify_args[2];
    verify_args[0].data = reinterpret_cast<const unsigned char*>(canonical.data());
    verify_args[0].len = canonical.size();
    verify_args[1].data = signature.data();
    verify_args[1].len = signature.size();
    NativeCallResult verify_call{};
    const bool table_ok = invoke_native_fn(kNativeFnVerifyEd25519, slot, verify_args, 2, verify_call)
            && verify_call.ok
            && slot->verify_result == 1;
    // B7-2 native self-test: a forced EVP_DigestVerify result is not enough because a second,
    // independent EVP_DigestVerify call (separate EVP_MD_CTX pool) must agree as well. A real
    // Frida acceptance run is still unexecuted (reported as such).
    const bool independent_ok = ed25519_verify_independent(
            reinterpret_cast<const unsigned char*>(canonical.data()), canonical.size(),
            signature.data(), signature.size());
    const bool verified = table_ok && independent_ok;
    secure_wipe(verify_call.bytes, sizeof(verify_call.bytes));
    if (!verified) {
        wipe_slot_locked(*slot);
        return auth_poison_result(hwid_bytes);
    }

    // 5. X25519 + HKDF(wrap_key) + AES-256-GCM unwrap content_key.
    unsigned char shared[64];
    size_t shared_len = sizeof(shared);
    if (!x25519_shared(g_client_priv, ephemeral.data(), shared, &shared_len) || shared_len != 32) {
        wipe_slot_locked(*slot);
        return auth_poison_result(hwid_bytes);
    }
    unsigned char wrap_key[32];
    const unsigned char info[] = "chimera/wrap/v1";
    if (!hkdf_sha256(shared, shared_len, nonce.data(), nonce.size(),
                     info, sizeof(info) - 1, wrap_key, sizeof(wrap_key))) {
        wipe_slot_locked(*slot);
        return auth_poison_result(hwid_bytes);
    }

    std::string account_for_aad;
    if (!find_string(json, "account", account_for_aad)) account_for_aad = account;
    std::string aad = "chimera-wrap/v1|" + account_for_aad + "|";
    aad.append(reinterpret_cast<const char*>(hwid_bytes.data()), hwid_bytes.size());

    unsigned char content_key[32];
    size_t content_len = sizeof(content_key);
    if (!aes_gcm_decrypt(wrap_key, wrapped.data(), 12, wrapped.data() + 12, 32,
                         wrapped.data() + 44, 16,
                         reinterpret_cast<const unsigned char*>(aad.data()), aad.size(),
                         content_key, &content_len) || content_len != 32) {
        wipe_slot_locked(*slot);
        return auth_poison_result(hwid_bytes);
    }

    // KI-28: resource_ck envelope (when present) wraps the per-(account,hwid) ResourceKey with the
    // just-unwrapped UserContentKey. Missing/failed envelope falls back to UserContentKey so the
    // current e2e keeps working until the server/pipeline ships resource_ck (documented KI-28 gap).
    unsigned char resource_key_candidate[32];
    size_t resource_key_len = sizeof(resource_key_candidate);
    bool have_resource_key = false;
    {
        std::string resource_ck_b64;
        std::string resource_account = account_for_aad.empty() ? account : account_for_aad;
        if (find_string(json, "resource_ck", resource_ck_b64)) {
            std::vector<unsigned char> envelope;
            if (b64_decode(resource_ck_b64, envelope) && envelope.size() == 60) {
                unsigned char resource_wrap_key[32];
                const unsigned char wrap_label[] = "chimera/resource-wrap/v1";
                if (hkdf_sha256(content_key, 32, wrap_label, sizeof(wrap_label) - 1,
                                reinterpret_cast<const unsigned char*>(""), 0,
                                resource_wrap_key, sizeof(resource_wrap_key))) {
                    std::string resource_aad = "chimera-resource/v1|" + resource_account + "|";
                    resource_aad.append(reinterpret_cast<const char*>(hwid_bytes.data()),
                                        hwid_bytes.size());
                    have_resource_key = aes_gcm_decrypt(
                            resource_wrap_key, envelope.data(), 12, envelope.data() + 12, 32,
                            envelope.data() + 44, 16,
                            reinterpret_cast<const unsigned char*>(resource_aad.data()),
                            resource_aad.size(), resource_key_candidate, &resource_key_len)
                            && resource_key_len == 32;
                    secure_wipe(resource_wrap_key, sizeof(resource_wrap_key));
                }
                secure_wipe(envelope.data(), envelope.size());
            }
        }
    }

    std::memcpy(slot->key, content_key, 32);
    const unsigned char* key_to_seal = have_resource_key ? resource_key_candidate : content_key;
    if (!seal_slot_key(*slot, key_to_seal)) {
        // No KEK means we cannot protect the key at rest; refuse rather than store it in the clear.
        secure_wipe(resource_key_candidate, sizeof(resource_key_candidate));
        return -10;
    }
    slot->resource_key_set = 1;
    secure_wipe(resource_key_candidate, sizeof(resource_key_candidate));
    // Layer 2: hand the class-body key to CNG now that the slot is sealed and marked. Failing here
    // means every class body would stay ciphertext, so treat it as an activation failure.
    if (!install_class_key(*slot)) {
        return -10;
    }
    unsigned char session_nonce[32];
    unsigned char session_const[32];
    if (!derive_session_nonce_locked(*slot, session_nonce)
            || !derive_session_const_locked(*slot, session_const)) {
        secure_wipe(shared, sizeof(shared));
        secure_wipe(wrap_key, sizeof(wrap_key));
        secure_wipe(content_key, sizeof(content_key));
        wipe_slot_locked(*slot);
        return auth_poison_result(hwid_bytes);
    }
    const uint64_t mixed = handle_mix_bits(slot->verify_result, session_nonce);
    unsigned char decision_tag[32];
    compute_verify_tag(slot->verify_result, session_nonce, session_const, decision_tag);
    apply_verify_decision_locked(*slot, decision_tag, session_nonce, session_const,
                                 static_cast<int>(slot->verify_result));
    secure_wipe(decision_tag, sizeof(decision_tag));
    secure_wipe(session_nonce, sizeof(session_nonce));
    secure_wipe(session_const, sizeof(session_const));
    secure_wipe(shared, sizeof(shared));
    secure_wipe(wrap_key, sizeof(wrap_key));
    secure_wipe(content_key, sizeof(content_key));
#if defined(CHIMERA_DEV_BUILD)
    // Dev/test DLL: the C++ AOT path completes CALL_NATIVE -> tag -> VERIFY_DECISION internally, so a
    // genuine activation ends VALID and the existing B1 canary tests keep working.
    if (slot->state != kHandleValid) {
        wipe_slot_locked(*slot);
        return auth_poison_result(hwid_bytes);
    }
#else
    // Release: strict PENDING (lead red line). Only the VM-side op7 VERIFY_DECISION may promote the
    // handle; Java must not fake it. Java therefore observes canary=0 until B7 step 2 VM wiring lands.
    slot->state = kHandlePending;
#endif
    slot->handle = (random_u64() ^ mixed) & 0x7fffffffffffffffULL;
    if (slot->handle == 0) slot->handle = 1;
    return static_cast<jlong>(slot->handle);
}

JNIEXPORT jint JNICALL Java_dev_chimera_runtime_ChimeraRuntime_nativeVerifyHeartbeat(
        JNIEnv* env, jclass, jbyteArray response, jbyteArray token) {
    ensure_lock();
    LockGuard guard;
    if (!code_section_intact()) {
        return 0;
    }
    if (should_poison() || !g_have_server_pub) {
        return 0;
    }
    auto response_bytes = jbyte_array(env, response);
    auto token_bytes = jbyte_array(env, token);
    std::string json(response_bytes.begin(), response_bytes.end());
    std::string token_text(token_bytes.begin(), token_bytes.end());

    std::string nonce_b64, signature_b64;
    long long expires_at = 0, issued_at = 0, sequence = 0;
    if (!find_string(json, "server_nonce", nonce_b64)
            || !find_string(json, "signature", signature_b64)
            || !find_long(json, "expires_at", expires_at)
            || !find_long(json, "issued_at", issued_at)
            || !find_long(json, "sequence", sequence)) {
        return 0;
    }
    std::vector<unsigned char> signature;
    if (!b64_decode(signature_b64, signature) || signature.size() != 64) {
        return 0;
    }
    std::string canonical = "{\"expires_at\":" + std::to_string(expires_at)
            + ",\"issued_at\":" + std::to_string(issued_at)
            + ",\"sequence\":" + std::to_string(sequence)
            + ",\"server_nonce\":\"" + nonce_b64
            + "\",\"token\":\"" + token_text + "\"}";
    if (!ed25519_verify(g_server_pub,
                        reinterpret_cast<const unsigned char*>(canonical.data()),
                        canonical.size(), signature.data(), signature.size())) {
        return 0;
    }
    return 1;
}

JNIEXPORT jlong JNICALL Java_dev_chimera_runtime_ChimeraRuntime_nativeCheckHandle(
        JNIEnv*, jclass, jlong handle) {
    ensure_lock();
    LockGuard guard;
    if (!code_section_intact()) {
        // B3-1: patched code section -> same-shape poison instead of a usable state hash.
        const std::vector<unsigned char> poisoned =
                poison_bytes(static_cast<uint64_t>(handle), 8);
        uint64_t value = 0;
        std::memcpy(&value, poisoned.data(), sizeof(value));
        return static_cast<jlong>(value);
    }
    unsigned char seed[8 + 32 + 16 + 4];
    std::memset(seed, 0, sizeof(seed));
    uint64_t h = static_cast<uint64_t>(handle);
    std::memcpy(seed, &h, sizeof(h));
    HandleSlot* slot = find_handle_locked(h);
    if (slot != nullptr) {
        std::memcpy(seed + 8, slot->key, 32);
        std::memcpy(seed + 40, slot->nonce, 16);
        std::memcpy(seed + 56, &slot->state, sizeof(slot->state));
    } else {
        uint64_t tick = GetTickCount64();
        std::memcpy(seed + 8, &tick, sizeof(tick));
    }
    unsigned char digest[32];
    SHA256(seed, sizeof(seed), digest);
    uint64_t value = 0;
    std::memcpy(&value, digest, sizeof(value));
    return static_cast<jlong>(value);
}

JNIEXPORT jbyteArray JNICALL Java_dev_chimera_runtime_ChimeraRuntime_nativeCompute(
        JNIEnv* env, jclass, jlong handle, jbyteArray params) {
    ensure_lock();
    LockGuard guard;
    static unsigned char s_b7_params[kMaxB7Params];
    const jsize input_len = params != nullptr ? env->GetArrayLength(params) : 0;
    if (input_len < 0 || input_len > static_cast<jsize>(kMaxB7Params)) {
        return env->NewByteArray(0);
    }
    if (input_len > 0) {
        env->GetByteArrayRegion(params, 0, input_len, reinterpret_cast<jbyte*>(s_b7_params));
    }
    const unsigned char op = input_len > 0 ? s_b7_params[0] : 0;
    if (!code_section_intact()) {
        // B3-1: fail closed. Canary (op 5) reports 0; B7 ops return empty; legacy ops keep poison bytes.
        if (op >= 6 && op <= 9) return env->NewByteArray(0);
        std::vector<unsigned char> result;
        if (op == 5) append_u64_be(result, 0ULL);
        else result = poison_bytes(static_cast<uint64_t>(handle), op == 4 ? 8 : 32);
        return make_byte_array(env, result);
    }
    HandleSlot* slot = find_handle_locked(static_cast<uint64_t>(handle));
    if (op >= 6 && op <= 10) {
        // B7 op6..op10: fixed stack/arena buffers, no std::vector growth on the success path.
        const bool allowed = slot != nullptr
                && (slot->state == kHandleValid
                    || ((op == 7 || op == 10) && slot->state == kHandlePending));
        if (!allowed) {
            if (op == 10 && slot == nullptr && handle != 0) {
                jbyteArray zeros = env->NewByteArray(32);
                if (zeros != nullptr) {
                    unsigned char zero_bytes[32] = {};
                    env->SetByteArrayRegion(zeros, 0, 32,
                                            reinterpret_cast<const jbyte*>(zero_bytes));
                }
                return zeros;
            }
            if ((op == 7 || op == 10) && slot != nullptr) {
                jbyteArray zeros = env->NewByteArray(32);
                if (zeros != nullptr) {
                    unsigned char zero_bytes[32] = {};
                    env->SetByteArrayRegion(zeros, 0, 32,
                                            reinterpret_cast<const jbyte*>(zero_bytes));
                }
                return zeros;
            }
            return env->NewByteArray(0);
        }
        arena_reset();
        unsigned char* out = static_cast<unsigned char*>(arena_alloc(kArenaSize, 16));
        size_t out_len = 0;
        const bool ok = out != nullptr
                && compute_b7_locked(*slot, s_b7_params, static_cast<size_t>(input_len),
                                     out, kArenaSize, &out_len);
        jbyteArray array = nullptr;
        if (ok) {
            array = env->NewByteArray(static_cast<jsize>(out_len));
            if (array != nullptr && out_len > 0) {
                env->SetByteArrayRegion(array, 0, static_cast<jsize>(out_len),
                                        reinterpret_cast<const jbyte*>(out));
            }
        }
        if (out != nullptr && out_len > 0) secure_wipe(out, out_len);
        arena_wipe_and_reset();
        return array != nullptr ? array : env->NewByteArray(0);
    }
    std::vector<unsigned char> input(s_b7_params, s_b7_params + input_len);
    std::vector<unsigned char> result;
    if (slot != nullptr && slot->state == kHandleValid) {
        result = compute_locked(*slot, input.data(), input.size());
    } else {
        // Same failure shape for invalid/poison handles; no exception escapes to Java.
        if (op == 5) append_u64_be(result, 0ULL);
        else result = poison_bytes(static_cast<uint64_t>(handle), op == 4 ? 8 : 32);
    }
    if (result.empty() && !input.empty() && input[0] == 5) {
        append_u64_be(result, 0ULL);
    }
    return make_byte_array(env, result);
}

// P1-1: class-body (CHENC1) key. HKDF-SHA256 over the ResourceKey that only an authorized handle
// holds, so the agent jar carries no key material at all: no valid handle -> empty array -> the
// agent halts instead of decrypting. The build derives the same 32 bytes from the same ResourceKey
// (dev.chimera.core.ClassKeyDerivation); ClassKeyAlignmentTest asserts both sides agree byte for
// byte. Never falls back to slot.key (the legacy content key) and never logs the result.
//
// Virtualized by VMProtect: this is the function an attacker actually wants to patch (it decides
// whether a key comes back at all), and until 2026-10-22 it was plain machine code - "xor eax,eax"
// in front of it disabled class-body encryption entirely. Written with a single exit point so the
// CHIMERA_VMP_BEGIN/END pair stays balanced.
//
// P0-2 (red team, both reviews): RELEASE builds no longer return the key. It used to be a public
// static Java method away - one reflective call on any licensed machine, then 1156 bodies decrypt
// offline with a 60-line script. The release symbol now returns an empty array; decryption lives in
// nativeDecryptClass() below. The dev build keeps the real implementation because
// ClassKeyAlignmentTest needs to assert that native's HKDF matches the build-time derivation.
JNIEXPORT jbyteArray JNICALL Java_dev_chimera_runtime_ChimeraRuntime_nativeDeriveClassKey(
        JNIEnv* env, jclass, jlong handle) {
#if defined(CHIMERA_DEV_BUILD)
    CHIMERA_VMP_BEGIN("chimera.classkey.derive");
    ensure_lock();
    LockGuard guard;
    unsigned char out[32];
    std::vector<unsigned char> result;
    // Cross-check (VM mode): the DLL refuses the class key on its own, so patching the Java-side
    // "make this class an empty stub" branch does not restore functionality - the bodies stay
    // ciphertext and cannot be loaded. The decision therefore does not live in Java alone.
    bool ok = code_section_intact() && !is_virtual_machine();
    if (ok) {
        HandleSlot* slot = find_handle_locked(static_cast<uint64_t>(handle));
        ok = slot != nullptr && slot->state == kHandleValid && slot->resource_key_set != 0;
        if (ok) {
            SlotKey resource_key(*slot);
            ok = resource_key.ok;
            if (ok) {
                const unsigned char salt[] = "chimera-classenc-v1";
                const unsigned char info[] = "class-key";
                ok = hkdf_sha256(resource_key.data(), 32, salt, sizeof(salt) - 1,
                                 info, sizeof(info) - 1, out, sizeof(out));
            }
        }
    }
    if (ok) result.assign(out, out + sizeof(out));
    secure_wipe(out, sizeof(out));
    CHIMERA_VMP_END();
    return make_byte_array(env, result);
#else
    // Release: no key ever crosses the JNI boundary. Kept as an exported symbol so an older agent
    // fails closed (empty array -> halt) instead of dying with UnsatisfiedLinkError mid-launch.
    (void) handle;
    return env->NewByteArray(0);
#endif
}

// ------------------------------------------------------- P0-2: class-body decryption in native
//
// CHENC1 layout (must match dev.chimera.attach.AgentCipher):
//   "CHENC1\0" | ver u8 | flags u8 | origLen u32be | crc32 u32be | nonce[12] | AES-256-GCM ct||tag
// AAD is the class internal name, so a body cannot be replayed under another entry.
constexpr size_t kChencMagicLen = 7;
constexpr size_t kChencHeaderLen = 29;
constexpr size_t kChencTagLen = 16;

/**
 * Standard CRC-32 (0xEDB88320). Called under the handle lock, so the lazy table needs no guard.
 *
 * <p>noinline is load-bearing: with -O2 this loop is inlined into the VMProtect-virtualized
 * decrypt function, which makes every byte of every class body execute as VM bytecode. Measured
 * before the attribute: 866ms for one class, ~100s for the 1156-class startup.</p>
 */
#if defined(_MSC_VER)
__declspec(noinline)
#else
__attribute__((noinline))
#endif
static uint32_t crc32_bytes(const unsigned char* data, size_t length) {
    static uint32_t table[256];
    static bool ready = false;
    if (!ready) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t value = i;
            for (int bit = 0; bit < 8; bit++) {
                value = (value & 1u) ? (0xEDB88320u ^ (value >> 1)) : (value >> 1);
            }
            table[i] = value;
        }
        ready = true;
    }
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < length; i++) {
        crc = table[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

/**
 * P0-2: decrypts one class body with a key derived from the authorized handle.
 *
 * <p>The plaintext necessarily leaves this function (the JVM has to define the class), but the key
 * never does: an attacker who hooks the return value gets the same plaintext they could already
 * dump from memory, while an attacker who wants to decrypt the jar offline has nothing to reflect.
 * Any failure returns an empty array, which the caller must treat as fatal.</p>
 */
JNIEXPORT jbyteArray JNICALL
Java_dev_chimera_runtime_ChimeraRuntime_nativeDecryptClass(
        JNIEnv* env, jclass, jlong handle, jbyteArray blob, jbyteArray name) {
    CHIMERA_VMP_BEGIN("chimera.classbody.decrypt");
    ensure_lock();
    LockGuard guard;
    // Per-class hot path: is_virtual_machine() opens three registry keys and stats three driver
    // files, which is far too expensive to repeat 1156 times per launch. Evaluated once.
    static const int vm_cached = is_virtual_machine() ? 1 : 0;
    std::vector<unsigned char> result;
    const jsize blob_len = blob == nullptr ? 0 : env->GetArrayLength(blob);
    const jsize name_len = name == nullptr ? 0 : env->GetArrayLength(name);
    if (blob_len > static_cast<jsize>(kChencHeaderLen + kChencTagLen)
            && blob_len <= 8 * 1024 * 1024 && name_len > 0 && name_len < 512
            && code_section_intact() && vm_cached == 0) {
        std::vector<unsigned char> in(static_cast<size_t>(blob_len));
        std::vector<unsigned char> internal(static_cast<size_t>(name_len));
        env->GetByteArrayRegion(blob, 0, blob_len, reinterpret_cast<jbyte*>(in.data()));
        env->GetByteArrayRegion(name, 0, name_len, reinterpret_cast<jbyte*>(internal.data()));
        static const unsigned char kMagic[kChencMagicLen] = {'C', 'H', 'E', 'N', 'C', '1', 0};
        bool ok = std::memcmp(in.data(), kMagic, kChencMagicLen) == 0 && in[7] == 1;
        const uint32_t orig_len = ok ? read_u32_be(in.data() + 9) : 0;
        const uint32_t expected_crc = ok ? read_u32_be(in.data() + 13) : 0;
        const size_t ct_len = static_cast<size_t>(blob_len) - kChencHeaderLen - kChencTagLen;
        // GCM is a stream construction: the ciphertext is exactly as long as the plaintext, so a
        // header whose orig_len is smaller than ct_len is not a shorter plaintext, it is a lie.
        // The old check allowed orig_len <= ct_len, allocated `plain` at orig_len and then let
        // EVP_DecryptUpdate write ct_len bytes - a heap overflow that happens BEFORE the GCM tag is
        // verified, and encrypted class bodies are deliberately outside the manifest (GCM was
        // assumed to authenticate them). Requiring equality removes the whole class.
        ok = ok && orig_len > 0 && orig_len == ct_len && orig_len < (4u * 1024u * 1024u);
        HandleSlot* slot = ok ? find_handle_locked(static_cast<uint64_t>(handle)) : nullptr;
        ok = ok && slot != nullptr && slot->state == kHandleValid && slot->resource_key_set != 0;
        if (ok) {
            std::vector<unsigned char> plain(orig_len);
            size_t plain_len = plain.size();
            // Layer 2 (red team round 5): the class key is held by CNG, so there is no per-class
            // derivation and no stack copy of the key here. The key material never enters this
            // process's writable memory after install_class_key().
            ok = bcrypt_gcm_decrypt(in.data() + 17, 12,
                         in.data() + kChencHeaderLen, ct_len,
                         in.data() + kChencHeaderLen + ct_len, kChencTagLen,
                         internal.data(), internal.size(), plain.data(), &plain_len)
                    && plain_len == orig_len
                    && crc32_bytes(plain.data(), plain_len) == expected_crc;
            if (ok) result.swap(plain);
        }
    }
    CHIMERA_VMP_END();
    return make_byte_array(env, result);
}

/**
 * A2: per-class authorization gate.
 *
 * <p>Design borrowed from the PhantomShieldX/Hachimi build (see docs/HANDOVER-...-B.md §"Hachimi"):
 * authorization is NOT a single boolean the whole process consults, it is a per-class check that a
 * class's {@code <clinit>} has to pass before it may run. The agent injects
 * {@code ldc id; invokestatic nativeGateCheck(I)V} at the top of {@code <clinit>} for a selected set
 * of classes.</p>
 *
 * <p>Why this exists: after P0-2 an attacker still needs a licensed machine to get plaintext, but a
 * leaked/refilled build (re-encrypted, or refilled with dumped plaintext) would run for anybody.
 * With this gate, a recipient without a live session dies at the first gated class - so the crack
 * does not travel.</p>
 *
 * <p><b>Red team round 3 (2026-10-22) called the previous shape DECORATIVE</b>, correctly: it
 * returned an {@code int} token that Java tested with {@code ifne}, so any non-zero value passed,
 * and {@code ChimeraRuntime.classGate} was a three-line Java wrapper that a single
 * {@code return 1} patch turned into "always allow" for every gated class at once.</p>
 *
 * <p>Both halves are closed here:</p>
 * <ul>
 *   <li>the function is {@code void} - no verdict crosses the JNI boundary, so there is no value to
 *       fake and no branch in the class body to flip;</li>
 *   <li>the injected call targets this native method directly - there is no Java wrapper left in
 *       the path to rewrite;</li>
 *   <li>denial terminates the process here (exit 4, the same contract as every other fail-closed
 *       path), inside the VMP region, so the decision and the action cannot be separated.</li>
 * </ul>
 *
 * <p>Bypass cost after this change: patch the virtualized gate function, or delete the
 * {@code invokestatic} from every gated class body (each is CHENC1-encrypted and manifest-covered).
 * One Java patch no longer clears anything.</p>
 *
 * <p>Per-ID derivation (salt includes the id) means two call sites never share a token, so a bypass
 * learned at one class teaches nothing about the next. When the rollout reaches all classes, the
 * per-class values are also the natural carrier for fixup data.</p>
 *
 * <p>Dev DLLs never terminate: the gate is a no-op there so unit tests and unlicensed dev runs
 * survive. Only the release artifact enforces.</p>
 */
JNIEXPORT void JNICALL
Java_dev_chimera_runtime_ChimeraRuntime_nativeGateCheck(JNIEnv*, jclass, jint id) {
    CHIMERA_VMP_BEGIN("chimera.classgate");
    ensure_lock();
    LockGuard guard;
    static const int vm_cached = is_virtual_machine() ? 1 : 0;
    bool allowed = false;
    if (vm_cached == 0 && code_section_intact()) {
        const uint64_t now = GetTickCount64();
        for (size_t i = 0; i < kMaxHandles; i++) {
            HandleSlot& slot = g_handles[i];
            if (slot.state != kHandleValid || slot.resource_key_set == 0) continue;
            if (slot_expired_locked(slot, now)) continue;
            SlotKey resource_key(slot);
            if (!resource_key.ok) continue;
            char info[32];
            const int info_len = std::snprintf(info, sizeof(info), "class-gate-%d", id);
            unsigned char out[4] = {0, 0, 0, 0};
            if (info_len > 0
                    && hkdf_sha256(resource_key.data(), 32,
                            reinterpret_cast<const unsigned char*>("chimera-classgate-v1"), 20,
                            reinterpret_cast<const unsigned char*>(info),
                            static_cast<size_t>(info_len), out, sizeof(out))) {
                // The verdict is "a live, unexpired, key-bearing handle exists", which is exactly
                // what reaching this point establishes. It used to be `token != 0`, so a per-id HKDF
                // output whose leading four bytes happened to be zero (2^-32 per class) would kill a
                // paying customer. The derivation stays: it is the fixup carrier once the rollout
                // covers every class.
                allowed = true;
                secure_wipe(out, sizeof(out));
            }
            break;
        }
    }
#if !defined(CHIMERA_DEV_BUILD)
    // Release: the verdict is acted on here and never leaves this frame. `_Exit` (not `exit`)
    // because static destructors must not run on a poisoned process.
    if (!allowed) {
        std::_Exit(4);
    }
#else
    (void) allowed;
#endif
    CHIMERA_VMP_END();

}

// D: VMProtect's image CRC verdict, captured in JNI_OnLoad. -1 = not a VMP build.
static int g_vmp_image_crc = -1;

// ---------------------------------------------------------------- G: hardware id
//
// The v4 `hwid` used to be built in Java from hostname|os.name|os.arch|user.name - every one of
// those is a system property, so "-Duser.name=x" plus a hostname change defeated the per-account
// device limit entirely. The value now comes from firmware:
//   * SMBIOS type 1 (System Information) UUID - burned into the board, survives OS reinstall;
//   * the C: volume serial - survives a board swap of the disk, catches machines without SMBIOS.
// Both are read-only, no WMI (no extra process, no COM), and hashed so the raw identifiers never
// leave this function.
//
// A hardware change legitimately changes the value: the account then needs a rebind, which is an
// operator action (POST /admin/rebind), not a self-service flow - decided 2026-10-22.

/** Reads the SMBIOS type-1 UUID. False when the table is missing or the UUID is unset. */
static bool smbios_system_uuid(unsigned char out[16]) {
    const DWORD signature = 'RSMB';  // 'R','S','M','B' little-endian
    const DWORD size = GetSystemFirmwareTable(signature, 0, nullptr, 0);
    if (size < 8 || size > (1024 * 1024)) return false;
    std::vector<unsigned char> buffer(size);
    if (GetSystemFirmwareTable(signature, 0, buffer.data(), size) != size) return false;
    // RawSMBIOSData: used_method u8, major u8, minor u8, dmi_revision u8, length u32, table[]
    const size_t table_len = read_u32_be(buffer.data() + 4);
    if (table_len == 0 || 8 + table_len > size) return false;
    const unsigned char* table = buffer.data() + 8;
    size_t offset = 0;
    while (offset + 4 <= table_len) {
        const unsigned char type = table[offset];
        const unsigned char length = table[offset + 1];
        if (length < 4 || offset + length > table_len) break;
        if (type == 1 && length >= 0x19) {  // System Information, UUID at 0x08
            bool all_zero = true;
            bool all_ff = true;
            for (int i = 0; i < 16; i++) {
                const unsigned char value = table[offset + 0x08 + i];
                out[i] = value;
                if (value != 0x00) all_zero = false;
                if (value != 0xFF) all_ff = false;
            }
            return !all_zero && !all_ff;
        }
        if (type == 127) break;  // end-of-table
        // Skip the formatted area, then the double-NUL terminated string area.
        size_t next = offset + length;
        if (next + 1 < table_len && table[next] == 0 && table[next + 1] == 0) {
            next += 2;
        } else {
            while (next + 1 < table_len && !(table[next] == 0 && table[next + 1] == 0)) next++;
            next += 2;
        }
        offset = next;
    }
    return false;
}

/** G: 64 lowercase hex characters, or "" when neither firmware source is readable. */
JNIEXPORT jstring JNICALL
Java_dev_chimera_runtime_ChimeraRuntime_nativeHwid(JNIEnv* env, jclass) {
    unsigned char uuid[16];
    const bool have_uuid = smbios_system_uuid(uuid);
    DWORD volume_serial = 0;
    const bool have_serial = GetVolumeInformationA("C:\\", nullptr, 0, &volume_serial,
            nullptr, nullptr, nullptr, 0) != 0;
    if (!have_uuid && !have_serial) {
        return env->NewStringUTF("");
    }
    unsigned char material[16 + 4 + 16];
    size_t used = 0;
    if (have_uuid) {
        std::memcpy(material, uuid, 16);
        used += 16;
    }
    if (have_serial) {
        material[used++] = static_cast<unsigned char>((volume_serial >> 24) & 0xFF);
        material[used++] = static_cast<unsigned char>((volume_serial >> 16) & 0xFF);
        material[used++] = static_cast<unsigned char>((volume_serial >> 8) & 0xFF);
        material[used++] = static_cast<unsigned char>(volume_serial & 0xFF);
    }
    static const char kDomain[] = "chimera-hwid-v1";
    std::memcpy(material + used, kDomain, sizeof(kDomain) - 1);
    used += sizeof(kDomain) - 1;
    unsigned char digest[32];
    SHA256(material, used, digest);
    char hex[65];
    for (int i = 0; i < 32; i++) {
        std::snprintf(hex + i * 2, 3, "%02x", digest[i]);
    }
    hex[64] = '\0';
    secure_wipe(material, sizeof(material));
    secure_wipe(digest, sizeof(digest));
    return env->NewStringUTF(hex);
}

/**
 * D: 1 when VMProtect reports the image CRC as valid, 0 when it does not, -1 when this build has
 * no VMProtect SDK (dev DLL). Logged by the gate so the value is visible in gate-diag.log without
 * having to capture the game's stderr.
 */
JNIEXPORT jint JNICALL
Java_dev_chimera_runtime_ChimeraRuntime_nativeVmpImageCrc(JNIEnv*, jclass) {
    return static_cast<jint>(g_vmp_image_crc);
}

JNIEXPORT jint JNICALL Java_dev_chimera_runtime_ChimeraRuntime_nativeRevokeHandle(
        JNIEnv*, jclass, jlong handle) {
    ensure_lock();
    LockGuard guard;
    uint64_t h = static_cast<uint64_t>(handle);
    if (h == 0) return 0;
    for (size_t i = 0; i < kMaxHandles; i++) {
        if (g_handles[i].state != kHandleFree && g_handles[i].handle == h) {
            wipe_slot_locked(g_handles[i]);
            return 1;
        }
    }
    return 0;
}

JNIEXPORT jint JNICALL Java_dev_chimera_runtime_ChimeraRuntime_nativeRevokeAllHandles(
        JNIEnv*, jclass) {
    ensure_lock();
    LockGuard guard;
    jint count = 0;
    for (size_t i = 0; i < kMaxHandles; i++) {
        if (g_handles[i].state != kHandleFree) {
            wipe_slot_locked(g_handles[i]);
            count++;
        }
    }
    return count;
}

JNIEXPORT jlong JNICALL Java_dev_chimera_runtime_ChimeraRuntime_nativeHandleTtlMs(
        JNIEnv*, jclass) {
    ensure_lock();
    LockGuard guard;
    return static_cast<jlong>(g_handle_ttl_ms);
}

JNIEXPORT jlong JNICALL Java_dev_chimera_runtime_ChimeraRuntime_nativeSetHandleTtlMs(
        JNIEnv*, jclass, jlong ttl_ms) {
    ensure_lock();
    LockGuard guard;
#if defined(CHIMERA_DEV_BUILD)
    uint64_t value = ttl_ms > 0 ? static_cast<uint64_t>(ttl_ms) : kHandleTtlDefaultMs;
    if (value < kHandleTtlMinMs) value = kHandleTtlMinMs;
    if (value > kHandleTtlMaxMs) value = kHandleTtlMaxMs;
    g_handle_ttl_ms = value;
#else
    // Phase 0 (C-05): release DLLs keep the compiled-in sliding TTL; the setter is inert.
    (void) ttl_ms;
#endif
    return static_cast<jlong>(g_handle_ttl_ms);
}

#if defined(CHIMERA_DEV_BUILD)
// Dev/test build only (compiled out of release DLLs): backdates the slot so the production TTL
// expiry path can be exercised without waiting ten minutes.
JNIEXPORT jint JNICALL Java_dev_chimera_runtime_ChimeraRuntime_nativeExpireHandleForTest(
        JNIEnv*, jclass, jlong handle) {
    ensure_lock();
    LockGuard guard;
    uint64_t h = static_cast<uint64_t>(handle);
    if (h == 0) return 0;
    for (size_t i = 0; i < kMaxHandles; i++) {
        if (g_handles[i].state != kHandleFree && g_handles[i].handle == h) {
            uint64_t back = g_handle_ttl_ms + 1000ULL;
            g_handles[i].last_used =
                    g_handles[i].last_used > back ? g_handles[i].last_used - back : 0ULL;
            return 1;
        }
    }
    return 0;
}
#endif  // CHIMERA_DEV_BUILD

// 1 = dev/test DLL (QA hooks + short TTL allowed), 0 = release DLL. Not a security control; lets
// tests and release audits assert which artifact is loaded.
JNIEXPORT jint JNICALL Java_dev_chimera_runtime_ChimeraRuntime_nativeDevBuild(
        JNIEnv*, jclass) {
#if defined(CHIMERA_DEV_BUILD)
    return 1;
#else
    return 0;
#endif
}

JNIEXPORT void JNICALL Java_dev_chimera_runtime_ChimeraRuntime_nativeSetAntiDebugMode(
        JNIEnv*, jclass, jint mode) {
    LONG clamped = mode;
    if (clamped < kAntiDebugTelemetry || clamped > kAntiDebugOff) clamped = kAntiDebugTelemetry;
#if !defined(CHIMERA_DEV_BUILD)
    // Phase 0 (C-02): release DLLs never accept the "off" downgrade from any caller.
    if (clamped == kAntiDebugOff) clamped = kAntiDebugTelemetry;
#endif
    InterlockedExchange(&g_anti_debug_mode, clamped);
}

JNIEXPORT jint JNICALL Java_dev_chimera_runtime_ChimeraRuntime_nativeAntiDebugSignalCount(
        JNIEnv*, jclass) {
    return static_cast<jint>(InterlockedCompareExchange(&g_anti_debug_signals, 0, 0));
}

// B4: monotonic high-resolution clocks for the Java-side timing window.
JNIEXPORT jlong JNICALL Java_dev_chimera_runtime_ChimeraRuntime_nativeQpcNanos(
        JNIEnv*, jclass) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER counter;
    if (QueryPerformanceFrequency(&frequency) == 0 || frequency.QuadPart <= 0
            || QueryPerformanceCounter(&counter) == 0) {
        return -1;
    }
    const long long seconds = counter.QuadPart / frequency.QuadPart;
    const long long remainder = counter.QuadPart % frequency.QuadPart;
    return static_cast<jlong>(seconds * 1000000000LL
            + (remainder * 1000000000LL) / frequency.QuadPart);
}

JNIEXPORT jlong JNICALL Java_dev_chimera_runtime_ChimeraRuntime_nativeWallClockNanos(
        JNIEnv*, jclass) {
    return static_cast<jlong>(GetTickCount64() * 1000000ULL);
}

// B6: 1 = JVMTI GetBytecodes ready, 0 = unavailable (Java falls back to the pre-define hash).
JNIEXPORT jint JNICALL Java_dev_chimera_runtime_ChimeraRuntime_nativeJvmtiAvailable(
        JNIEnv*, jclass) {
    return (g_jvmti != nullptr && g_jvmti_bytecodes) ? 1 : 0;
}

// B6: hash the METHOD BYTECODE ARRAY (JVMTI GetBytecodes) that the VM installed for the hidden
// class after defineHiddenClass. Java hashes the decrypted run-method Code[] as expected SHA-256.
// Returns 1 = any method bytecode matches expected, 0 = mismatch/tampered, -1 = unavailable/error.
JNIEXPORT jint JNICALL Java_dev_chimera_runtime_ChimeraRuntime_nativeHiddenClassBytesMatch(
        JNIEnv* env, jclass, jclass hidden_class, jbyteArray expected_sha256) {
    if (g_jvmti == nullptr || !g_jvmti_bytecodes || hidden_class == nullptr
            || expected_sha256 == nullptr) {
        return -1;
    }
    if (env->GetArrayLength(expected_sha256) != 32) return -1;
    unsigned char expected[32];
    env->GetByteArrayRegion(expected_sha256, 0, 32, reinterpret_cast<jbyte*>(expected));
    // JVMTI GetBytecodes takes a jmethodID and returns that method's bytecode array; try every
    // method of the hidden fragment (run/<init>) and accept any match against Java's run-Code hash.
    jint method_count = 0;
    jmethodID* methods = nullptr;
    if (g_jvmti->GetClassMethods(hidden_class, &method_count, &methods) != JVMTI_ERROR_NONE
            || methods == nullptr || method_count <= 0) {
        secure_wipe(expected, sizeof(expected));
        return -1;
    }
    // GetBytecodes returns the METHOD bytecode array (not a full classfile). Java hashes the
    // decrypted "run" method Code[]; iterate every method and accept a match from any of them
    // (<init> is checked first on some VMs, so a first-method-only comparison would be wrong).
    int result = -1;
    bool saw_any = false;
    for (jint i = 0; i < method_count; i++) {
        unsigned char* method_code = nullptr;
        jint code_len = 0;
        if (g_jvmti->GetBytecodes(methods[i], &code_len, &method_code) != JVMTI_ERROR_NONE
                || method_code == nullptr || code_len <= 0) {
            continue;
        }
        saw_any = true;
        unsigned char digest[32];
        SHA256(method_code, static_cast<size_t>(code_len), digest);
        if (CRYPTO_memcmp(digest, expected, sizeof(digest)) == 0) result = 1;
        secure_wipe(digest, sizeof(digest));
        g_jvmti->Deallocate(method_code);
        if (result == 1) break;
    }
    g_jvmti->Deallocate(reinterpret_cast<unsigned char*>(methods));
    secure_wipe(expected, sizeof(expected));
    return saw_any ? (result == 1 ? 1 : 0) : -1;
}
// ================================================================== S5 production exports
// C-4: nativeRegisterHiddenClass removed with the dead native DefineClass path. Nothing registers
// hidden classes any more: S1 entries are loaded by name through the Fabric class loader.

// C-4: nativeIsHiddenClassRegistered removed together with the registry it queried.

JNIEXPORT jint JNICALL Java_dev_chimera_runtime_ChimeraRuntime_nativeAntiDumpProbe(
        JNIEnv*, jclass) {
    return s5_anti_dump_cached_mask();
}

JNIEXPORT jint JNICALL Java_dev_chimera_runtime_ChimeraRuntime_nativeAntiDumpSignalCount(
        JNIEnv*, jclass) {
    return static_cast<jint>(InterlockedCompareExchange(&g_s5_anti_dump_signal_count, 0, 0));
}

JNIEXPORT jint JNICALL Java_dev_chimera_runtime_ChimeraRuntime_nativeSetPayloadContext(
        JNIEnv* env, jclass, jbyteArray env_salt) {
    if (env_salt == nullptr) return 0;
    const jsize length = env->GetArrayLength(env_salt);
    if (length < 8 || length > static_cast<jsize>(sizeof(g_s5_payload_env_salt))) return 0;
    unsigned char buffer[64] = {};
    env->GetByteArrayRegion(env_salt, 0, length, reinterpret_cast<jbyte*>(buffer));
    ensure_lock();
    LockGuard guard;
    secure_wipe(g_s5_payload_env_salt, sizeof(g_s5_payload_env_salt));
    std::memcpy(g_s5_payload_env_salt, buffer, static_cast<size_t>(length));
    g_s5_payload_env_salt_len = static_cast<size_t>(length);
    secure_wipe(buffer, sizeof(buffer));
    return 1;
}

JNIEXPORT jint JNICALL Java_dev_chimera_runtime_ChimeraRuntime_nativePayloadAvailable(
        JNIEnv*, jclass) {
    std::vector<unsigned char> ciphertext;
    unsigned char nonce[12];
    unsigned char tag[16];
    return s5_payload_info(&ciphertext, nonce, tag) ? 1 : 0;
}

JNIEXPORT jlong JNICALL Java_dev_chimera_runtime_ChimeraRuntime_nativePayloadSize(
        JNIEnv*, jclass) {
    std::vector<unsigned char> ciphertext;
    unsigned char nonce[12];
    unsigned char tag[16];
    return s5_payload_info(&ciphertext, nonce, tag)
            ? static_cast<jlong>(ciphertext.size()) : 0;
}

JNIEXPORT jbyteArray JNICALL Java_dev_chimera_runtime_ChimeraRuntime_nativePayloadDigest(
        JNIEnv* env, jclass) {
    std::vector<unsigned char> ciphertext;
    unsigned char nonce[12];
    unsigned char tag[16];
    std::vector<unsigned char> digest;
    if (s5_payload_info(&ciphertext, nonce, tag) && !ciphertext.empty()) {
        unsigned char hash[32];
        SHA256(ciphertext.data(), ciphertext.size(), hash);
        digest.assign(hash, hash + 32);
        secure_wipe(hash, sizeof(hash));
    }
    return make_byte_array(env, digest);
}

JNIEXPORT jbyteArray JNICALL Java_dev_chimera_runtime_ChimeraRuntime_nativePayloadExtract(
        JNIEnv* env, jclass, jlong handle, jint offset, jint length) {
    std::vector<unsigned char> result;
    if (offset < 0 || length <= 0) return make_byte_array(env, result);
    std::vector<unsigned char> ciphertext;
    unsigned char nonce[12];
    unsigned char tag[16];
    if (!s5_payload_info(&ciphertext, nonce, tag) || ciphertext.size() <= 16) {
        return make_byte_array(env, result);
    }
    ensure_lock();
    LockGuard guard;
    HandleSlot* slot = find_handle_locked(static_cast<uint64_t>(handle));
    if (slot == nullptr || slot->state != kHandleValid) return make_byte_array(env, result);
    unsigned char key[32];
    if (!s5_derive_payload_key(*slot, key)) return make_byte_array(env, result);
    // Contract: ciphertext length = footer.len; the GCM tag is the footer's 16B tag (not the last
    // 16 bytes of the ciphertext region). AAD is null/empty.
    std::vector<unsigned char> plain(ciphertext.size());
    size_t plain_len = 0;
    const bool ok = aes_gcm_decrypt(key, nonce, 12, ciphertext.data(), ciphertext.size(),
                                    tag, 16, nullptr, 0, plain.data(), &plain_len);
    secure_wipe(key, sizeof(key));
    if (ok && plain_len >= static_cast<size_t>(offset)
            && static_cast<size_t>(length) <= plain_len - static_cast<size_t>(offset)) {
        result.assign(plain.begin() + offset, plain.begin() + offset + length);
    }
    secure_wipe(plain.data(), plain.size());
    return make_byte_array(env, result);
}

#if defined(CHIMERA_DEV_BUILD)
// Dev-only aliases for native smoke tests; never exported by release DLLs.
JNIEXPORT jint JNICALL Java_dev_chimera_runtime_S5NativeTest_nativeAntiDumpProbeForTest(
        JNIEnv*, jclass) { return s5_anti_dump_cached_mask(); }
JNIEXPORT jint JNICALL Java_dev_chimera_runtime_S5NativeTest_nativeSetPayloadContextForTest(
        JNIEnv* env, jclass, jbyteArray env_salt) {
    if (env_salt == nullptr) return 0;
    const jsize length = env->GetArrayLength(env_salt);
    if (length < 8 || length > 64) return 0;
    unsigned char buffer[64] = {};
    env->GetByteArrayRegion(env_salt, 0, length, reinterpret_cast<jbyte*>(buffer));
    ensure_lock();
    LockGuard guard;
    secure_wipe(g_s5_payload_env_salt, sizeof(g_s5_payload_env_salt));
    std::memcpy(g_s5_payload_env_salt, buffer, static_cast<size_t>(length));
    g_s5_payload_env_salt_len = static_cast<size_t>(length);
    secure_wipe(buffer, sizeof(buffer));
    return 1;
}

JNIEXPORT jint JNICALL Java_dev_chimera_runtime_S5NativeTest_nativePayloadAvailableForTest(
        JNIEnv*, jclass) {
    std::vector<unsigned char> ciphertext;
    unsigned char nonce[12];
    unsigned char tag[16];
    return s5_payload_info(&ciphertext, nonce, tag) ? 1 : 0;
}
JNIEXPORT jint JNICALL Java_dev_chimera_runtime_S5NativeTest_nativeHiddenRegistryCountForTest(
        JNIEnv*, jclass) { return static_cast<jint>(g_s5_hidden_registry_count); }
JNIEXPORT jlong JNICALL Java_dev_chimera_runtime_S5NativeTest_nativeInstallPayloadTestHandleForTest(
        JNIEnv* env, jclass, jbyteArray resource_key) {
    std::vector<unsigned char> key = jbyte_array(env, resource_key);
    if (key.size() != 32) return 0;
    ensure_lock();
    LockGuard guard;
    unsigned char nonce[16];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) return 0;
    HandleSlot* slot = store_handle_slot_locked(key.data(), nonce, kHandleValid);
    seal_slot_key(*slot, key.data());
    slot->resource_key_set = 1;
    secure_wipe(nonce, sizeof(nonce));
    return static_cast<jlong>(slot->handle);
}

JNIEXPORT jbyteArray JNICALL Java_dev_chimera_runtime_S5NativeTest_nativePayloadExtractForTest(
        JNIEnv* env, jclass, jlong handle, jint offset, jint length) {
    return Java_dev_chimera_runtime_ChimeraRuntime_nativePayloadExtract(env, nullptr, handle,
                                                                         offset, length);
}

JNIEXPORT jlong JNICALL Java_dev_chimera_runtime_S5NativeTest_nativePayloadSizeForTest(
        JNIEnv* env, jclass) {
    return Java_dev_chimera_runtime_ChimeraRuntime_nativePayloadSize(env, nullptr);
}

JNIEXPORT jbyteArray JNICALL Java_dev_chimera_runtime_S5NativeTest_nativePayloadDigestForTest(
        JNIEnv* env, jclass) {
    return Java_dev_chimera_runtime_ChimeraRuntime_nativePayloadDigest(env, nullptr);
}
#endif  // CHIMERA_DEV_BUILD

// B3-1: 1 = own .text SHA-256 baseline matches and no protected prologue was patched; 0 = tampered
// or baseline unavailable. Same-shape integer query; never throws.
JNIEXPORT jint JNICALL Java_dev_chimera_runtime_ChimeraRuntime_nativeCodeSectionIntact(
        JNIEnv*, jclass) {
    ensure_lock();
    LockGuard guard;
    return code_section_intact_fresh() ? 1 : 0;
}

#if defined(CHIMERA_DEV_BUILD)
// QA-only tamper simulation: rewrites the first 5 bytes of aes_gcm_decrypt (INT3 or JMP rel32) so
// tests can prove baseline/hot-entry detection without an external debugger. aes_gcm_decrypt is only
// reached from the license handshake, so no heartbeat/background path executes the patched bytes.
// Never shipped.
unsigned char g_saved_code_bytes[5];
unsigned char* g_patched_code_address = nullptr;

JNIEXPORT jint JNICALL Java_dev_chimera_runtime_NativeCodeSectionTest_nativeCorruptCodeForTest(
        JNIEnv*, jclass, jint pattern) {
    if (g_patched_code_address != nullptr) return 0;
    const unsigned char opcode = (pattern == 0xE9) ? 0xE9 : 0xCC;
    auto* target = reinterpret_cast<unsigned char*>(&aes_gcm_decrypt);
    DWORD previous = 0;
    if (VirtualProtect(target, sizeof(g_saved_code_bytes), PAGE_EXECUTE_READWRITE, &previous) == 0) {
        return 0;
    }
    std::memcpy(g_saved_code_bytes, target, sizeof(g_saved_code_bytes));
    target[0] = opcode;
    if (opcode == 0xE9) std::memset(target + 1, 0, sizeof(g_saved_code_bytes) - 1);
    FlushInstructionCache(GetCurrentProcess(), target, sizeof(g_saved_code_bytes));
    DWORD ignored = 0;
    VirtualProtect(target, sizeof(g_saved_code_bytes), previous, &ignored);
    g_patched_code_address = target;
    invalidate_integrity_cache();
    return 1;
}

JNIEXPORT jint JNICALL Java_dev_chimera_runtime_NativeCodeSectionTest_nativeRestoreCodeForTest(
        JNIEnv*, jclass) {
    if (g_patched_code_address == nullptr) return 1;
    DWORD previous = 0;
    if (VirtualProtect(g_patched_code_address, sizeof(g_saved_code_bytes),
                       PAGE_EXECUTE_READWRITE, &previous) == 0) {
        return 0;
    }
    std::memcpy(g_patched_code_address, g_saved_code_bytes, sizeof(g_saved_code_bytes));
    FlushInstructionCache(GetCurrentProcess(), g_patched_code_address, sizeof(g_saved_code_bytes));
    DWORD ignored = 0;
    VirtualProtect(g_patched_code_address, sizeof(g_saved_code_bytes), previous, &ignored);
    g_patched_code_address = nullptr;
    invalidate_integrity_cache();
    return 1;
}
#endif  // CHIMERA_DEV_BUILD


#if defined(CHIMERA_DEV_BUILD)
// ---------------------------------------------------------------- B7 step 2 test hooks (dev only)
// Declared by dev.chimera.runtime.NativeB7Step2Test; compiled out of release DLLs.
JNIEXPORT jint JNICALL Java_dev_chimera_runtime_NativeB7Step2Test_nativeEd25519IndependentDebugForTest(
        JNIEnv* env, jclass, jbyteArray pub, jbyteArray msg, jbyteArray sig) {
    std::vector<unsigned char> pub_bytes = jbyte_array(env, pub);
    std::vector<unsigned char> msg_bytes = jbyte_array(env, msg);
    std::vector<unsigned char> sig_bytes = jbyte_array(env, sig);
    if (pub_bytes.size() != 32 || sig_bytes.size() != 64) return -1;
    int stages = 0;
    const bool ok = ed25519_verify_bn(pub_bytes.data(), msg_bytes.data(), msg_bytes.size(),
                                      sig_bytes.data(), 64, &stages);
    return (ok ? 1000 : 0) | stages;
}

JNIEXPORT jlong JNICALL Java_dev_chimera_runtime_NativeB7Step2Test_nativeInstallTestDecisionHandleForTest(
        JNIEnv* env, jclass, jbyteArray content_key, jbyteArray transcript, jbyteArray signature) {
    ensure_lock();
    LockGuard guard;
    std::vector<unsigned char> key = jbyte_array(env, content_key);
    std::vector<unsigned char> message = jbyte_array(env, transcript);
    std::vector<unsigned char> sig = jbyte_array(env, signature);
    if (key.size() != 32 || message.empty() || message.size() > 1024 || sig.size() != 64) return 0;
    unsigned char nonce[16];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) return 0;
    HandleSlot* slot = store_handle_slot_locked(key.data(), nonce, kHandlePending);
    slot->verify_result = 1;
    std::memcpy(slot->transcript, message.data(), message.size());
    slot->transcript_len = static_cast<uint16_t>(message.size());
    std::memcpy(slot->signature, sig.data(), 64);
    seal_slot_key(*slot, key.data());
    slot->resource_key_set = 1;
    secure_wipe(nonce, sizeof(nonce));
    return static_cast<jlong>(slot->handle);
}

JNIEXPORT jint JNICALL Java_dev_chimera_runtime_NativeB7Step2Test_nativeForcePendingForTest(
        JNIEnv*, jclass, jlong handle) {
    ensure_lock();
    LockGuard guard;
    HandleSlot* slot = find_handle_locked(static_cast<uint64_t>(handle));
    if (slot == nullptr) return 0;
    slot->state = kHandlePending;
    return 1;
}

JNIEXPORT jlong JNICALL Java_dev_chimera_runtime_NativeB7Step2Test_nativeHeapWindowBeginForTest(
        JNIEnv*, jclass) {
    InterlockedExchange(&g_heap_window_allocs, 0);
    InterlockedExchange(&g_heap_window_active, 1);
    return static_cast<jlong>(GetTickCount64());
}

JNIEXPORT jint JNICALL Java_dev_chimera_runtime_NativeB7Step2Test_nativeHeapWindowEndForTest(
        JNIEnv*, jclass) {
    InterlockedExchange(&g_heap_window_active, 0);
    return static_cast<jint>(InterlockedCompareExchange(&g_heap_window_allocs, 0, 0));
}

JNIEXPORT jint JNICALL Java_dev_chimera_runtime_NativeB7Step2Test_nativeHeapWindowAllocCountForTest(
        JNIEnv*, jclass) {
    return static_cast<jint>(InterlockedCompareExchange(&g_heap_window_allocs, 0, 0));
}

JNIEXPORT jint JNICALL Java_dev_chimera_runtime_NativeB7Step2Test_nativeHeapWindowSelfTestForTest(
        JNIEnv*, jclass) {
    InterlockedExchange(&g_heap_window_allocs, 0);
    InterlockedExchange(&g_heap_window_active, 1);
    b7_heap_note();
    b7_heap_note();
    InterlockedExchange(&g_heap_window_active, 0);
    return static_cast<jint>(InterlockedCompareExchange(&g_heap_window_allocs, 0, 0)) == 2 ? 1 : 0;
}

JNIEXPORT jlong JNICALL Java_dev_chimera_runtime_NativeB7Step2Test_nativeInstallTestHandleForTest(
        JNIEnv* env, jclass, jbyteArray content_key, jint state) {
    ensure_lock();
    LockGuard guard;
    std::vector<unsigned char> key = jbyte_array(env, content_key);
    if (key.size() != 32) return 0;
    uint32_t clamped = (state == kHandleValid || state == kHandlePending || state == kHandlePoison)
            ? static_cast<uint32_t>(state) : kHandlePending;
    unsigned char nonce[16];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) return 0;
    HandleSlot* slot = store_handle_slot_locked(key.data(), nonce, clamped);
    slot->verify_result = 1;
    secure_wipe(nonce, sizeof(nonce));
    return static_cast<jlong>(slot->handle);
}

JNIEXPORT jlong JNICALL Java_dev_chimera_runtime_NativeB7Step2Test_nativeInstallTestHandleWithResourceKeyForTest(
        JNIEnv* env, jclass, jbyteArray user_content_key, jbyteArray resource_key, jint state) {
    ensure_lock();
    LockGuard guard;
    std::vector<unsigned char> uck = jbyte_array(env, user_content_key);
    std::vector<unsigned char> rk = jbyte_array(env, resource_key);
    if (uck.size() != 32 || rk.size() != 32) return 0;
    uint32_t clamped = (state == kHandleValid || state == kHandlePending || state == kHandlePoison)
            ? static_cast<uint32_t>(state) : kHandlePending;
    unsigned char nonce[16];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) return 0;
    HandleSlot* slot = store_handle_slot_locked(uck.data(), nonce, clamped);
    slot->verify_result = 1;
    seal_slot_key(*slot, rk.data());
    slot->resource_key_set = 1;
    secure_wipe(nonce, sizeof(nonce));
    return static_cast<jlong>(slot->handle);
}
JNIEXPORT jbyteArray JNICALL Java_dev_chimera_runtime_NativeB7Step2Test_nativeSessionConstForTest(
        JNIEnv* env, jclass, jlong handle) {
    ensure_lock();
    LockGuard guard;
    std::vector<unsigned char> result;
    unsigned char out[32];
    HandleSlot* slot = find_handle_locked(static_cast<uint64_t>(handle));
    if (slot != nullptr && derive_session_const_locked(*slot, out)) result.assign(out, out + 32);
    secure_wipe(out, sizeof(out));
    return make_byte_array(env, result);
}

JNIEXPORT jbyteArray JNICALL Java_dev_chimera_runtime_NativeB7Step2Test_nativeSessionNonceForTest(
        JNIEnv* env, jclass, jlong handle) {
    ensure_lock();
    LockGuard guard;
    std::vector<unsigned char> result;
    unsigned char out[32];
    HandleSlot* slot = find_handle_locked(static_cast<uint64_t>(handle));
    if (slot != nullptr && derive_session_nonce_locked(*slot, out)) result.assign(out, out + 32);
    secure_wipe(out, sizeof(out));
    return make_byte_array(env, result);
}

JNIEXPORT jint JNICALL Java_dev_chimera_runtime_NativeB7Step2Test_nativeDecisionForTest(
        JNIEnv* env, jclass, jbyteArray tag, jlong handle) {
    ensure_lock();
    LockGuard guard;
    std::vector<unsigned char> tag_bytes = jbyte_array(env, tag);
    HandleSlot* slot = find_handle_locked(static_cast<uint64_t>(handle));
    if (slot == nullptr || tag_bytes.size() != 32) return -1;
    unsigned char params[33];
    params[0] = 7;
    std::memcpy(params + 1, tag_bytes.data(), 32);
    const bool ok = compute_b7_verify_decision(*slot, params, sizeof(params));
    secure_wipe(params, sizeof(params));
    return ok ? static_cast<jint>(slot->state) : -1;
}

JNIEXPORT jbyteArray JNICALL Java_dev_chimera_runtime_NativeB7Step2Test_nativeCallNativeForTest(
        JNIEnv* env, jclass, jint opaque_index, jbyteArray payload) {
    ensure_lock();
    LockGuard guard;
    std::vector<unsigned char> in = jbyte_array(env, payload);
    std::vector<unsigned char> result;
    if (in.size() < 2 || in[0] > 8 || in.size() < 2 + static_cast<size_t>(in[0]) * 32) {
        return make_byte_array(env, result);
    }
    const size_t argc = in[0];
    const size_t ret_kind = in[1];
    std::vector<unsigned char> params(5 + argc * 32);
    params[0] = 6;
    params[1] = static_cast<unsigned char>((static_cast<uint32_t>(opaque_index) >> 8) & 0xff);
    params[2] = static_cast<unsigned char>(static_cast<uint32_t>(opaque_index) & 0xff);
    params[3] = static_cast<unsigned char>(argc);
    params[4] = static_cast<unsigned char>(ret_kind);
    std::memcpy(params.data() + 5, in.data() + 2, argc * 32);
    HandleSlot temp{};
    temp.state = kHandleValid;
    temp.verify_result = 1;
    RAND_bytes(temp.key, 32);
    RAND_bytes(temp.nonce, 16);
    arena_reset();
    unsigned char* out = static_cast<unsigned char*>(arena_alloc(kArenaSize, 16));
    size_t out_len = 0;
    if (out != nullptr
            && compute_b7_call_native(temp, params.data(), params.size(), out, kArenaSize, &out_len)) {
        result.assign(out, out + out_len);
    }
    if (out != nullptr && out_len > 0) secure_wipe(out, out_len);
    arena_wipe_and_reset();
    secure_wipe(temp.key, sizeof(temp.key));
    secure_wipe(temp.nonce, sizeof(temp.nonce));
    return make_byte_array(env, result);
}

JNIEXPORT jlong JNICALL Java_dev_chimera_runtime_NativeB7Step2Test_nativeHandleMixForTest(
        JNIEnv* env, jclass, jlong base, jint verify_result, jbyteArray nonce) {
    std::vector<unsigned char> nonce_bytes = jbyte_array(env, nonce);
    if (nonce_bytes.size() != 32) return 0;
    const uint64_t mixed = handle_mix_bits(static_cast<uint64_t>(verify_result), nonce_bytes.data());
    uint64_t value = (static_cast<uint64_t>(base) ^ mixed) & 0x7fffffffffffffffULL;
    if (value == 0) value = 1;
    return static_cast<jlong>(value);
}

JNIEXPORT jint JNICALL Java_dev_chimera_runtime_NativeB7Step2Test_nativeSecureWipeSelfTestForTest(
        JNIEnv*, jclass) {
    unsigned char buffer[64];
    std::memset(buffer, 0xA5, sizeof(buffer));
    secure_wipe(buffer, sizeof(buffer));
    for (size_t i = 0; i < sizeof(buffer); i++) {
        if (buffer[i] != 0) return 0;
    }
    return 1;
}

JNIEXPORT jint JNICALL Java_dev_chimera_runtime_NativeB7Step2Test_nativeArenaResidueForTest(
        JNIEnv* env, jclass, jbyteArray needle) {
    ensure_lock();
    LockGuard guard;
    std::vector<unsigned char> bytes = jbyte_array(env, needle);
    if (bytes.empty() || g_arena_used < bytes.size()) return 0;
    int matches = 0;
    for (size_t i = 0; i + bytes.size() <= g_arena_used; i++) {
        if (std::memcmp(g_arena + i, bytes.data(), bytes.size()) == 0) matches++;
    }
    return matches;
}

JNIEXPORT jint JNICALL Java_dev_chimera_runtime_NativeB7Step2Test_nativeSetTestModeForTest(
        JNIEnv*, jclass, jint mode) {
    g_test_mode = mode != 0;
    invalidate_integrity_cache();
    return g_test_mode ? 1 : 0;
}

JNIEXPORT jint JNICALL Java_dev_chimera_runtime_NativeB7Step2Test_nativeTestModeForTest(
        JNIEnv*, jclass) {
    return g_test_mode ? 1 : 0;
}

JNIEXPORT jint JNICALL Java_dev_chimera_runtime_NativeB7Step2Test_nativeForceVerifyResultForTest(
        JNIEnv*, jclass, jint enabled, jint result) {
    g_force_verify_result_enabled = enabled != 0;
    g_force_verify_result = result != 0 ? 1 : 0;
    return 1;
}

JNIEXPORT jlong JNICALL Java_dev_chimera_runtime_NativeB7Step2Test_nativeArenaSizeForTest(
        JNIEnv*, jclass) {
    return static_cast<jlong>(kArenaSize);
}

JNIEXPORT jint JNICALL Java_dev_chimera_runtime_NativeB7Step2Test_nativeOpaqueIndexForTest(
        JNIEnv*, jclass, jint which) {
    switch (which) {
        case 0: return kNativeFnVerifyEd25519;
        case 1: return kNativeFnVerifyResultTag;
        case 2: return kNativeFnSha256;
        case 3: return kNativeFnHmac;
        case 4: return kNativeFnHkdf;
        case 5: return kNativeFnSessionNonce;
        default: return -1;
    }
}

JNIEXPORT jint JNICALL Java_dev_chimera_runtime_NativeB7Step2Test_nativeCorruptCodeForTest(
        JNIEnv*, jclass, jint pattern) {
    return Java_dev_chimera_runtime_NativeCodeSectionTest_nativeCorruptCodeForTest(
            nullptr, nullptr, pattern);
}

JNIEXPORT jint JNICALL Java_dev_chimera_runtime_NativeB7Step2Test_nativeRestoreCodeForTest(
        JNIEnv*, jclass) {
    return Java_dev_chimera_runtime_NativeCodeSectionTest_nativeRestoreCodeForTest(
            nullptr, nullptr);
}
#endif  // CHIMERA_DEV_BUILD

#if defined(CHIMERA_SINK_EXTERNAL_JNI_ONLOAD)
// B1: generated by NativeSinkTransformer (chimera_sink.cpp / registration).
extern "C" jint chimera_sink_register_all(JNIEnv*);
extern "C" jint chimera_sink_register_all_with_host(JNIEnv*, jclass);
#endif

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    ensure_lock();
    // B6: capture JVMTI and enable GetBytecodes for post-defineHiddenClass verification.
    {
        jvmtiEnv* env = nullptr;
        if (vm->GetEnv(reinterpret_cast<void**>(&env), JVMTI_VERSION_1_2) == JNI_OK
                && env != nullptr) {
            jvmtiCapabilities caps{};
            caps.can_get_bytecodes = 1;
            g_jvmti = env;
            g_jvmti_bytecodes = env->AddCapabilities(&caps) == JVMTI_ERROR_NONE;
        }
    }
    OPENSSL_init_crypto(0, nullptr);
    // B7 step 2: preallocate fixed crypto pools + arena; runtime paths must not grow them.
    g_verify_ctx_pool_ready = true;
    for (size_t i = 0; i < kVerifyCtxPoolSize; i++) {
        g_verify_ctx_pool[i] = EVP_MD_CTX_new();
        if (g_verify_ctx_pool[i] == nullptr) g_verify_ctx_pool_ready = false;
    }
    for (size_t i = 0; i < kVerifyCtxPoolSize; i++) {
        g_verify_independent_pool[i] = EVP_MD_CTX_new();
        if (g_verify_independent_pool[i] == nullptr) g_verify_ctx_pool_ready = false;
    }
    g_cipher_ctx_pool_ready = true;
    for (size_t i = 0; i < kCipherCtxPoolSize; i++) {
        g_cipher_ctx_pool[i] = EVP_CIPHER_CTX_new();
        if (g_cipher_ctx_pool[i] == nullptr) g_cipher_ctx_pool_ready = false;
    }
    arena_reset();
#if defined(CHIMERA_DEV_BUILD)
    // CHIMERA_TEST_MODE: dev DLL only; enables post-JNI_OnLoad Frida attach by skipping the B3-1
    // baseline and native anti-debug poisoning. Pool/concurrency and wall-clock defenses stay on.
    g_test_mode = env_flag_enabled("CHIMERA_TEST_MODE")
            || env_flag_enabled("CHIMERA_ALLOW_FRIDA");
    if (g_test_mode) {
        std::fprintf(stderr,
                "[chimera-native] CHIMERA_TEST_MODE: B3-1/anti-debug bypassed (dev DLL only)\n");
    }
#endif
    // Red team round 5: the per-process KEK that seals ResourceKeys at rest. Must exist before any
    // handle is created, otherwise seal_slot_key() fails closed and activation cannot complete.
    init_seal_kek();
    // B3-1: snapshot the executable section before any Java code can call into this module.
    init_code_integrity();
    // Red team round 3: hardware breakpoints are now swept by a dedicated thread, so the sweep also
    // covers the threads that actually run the decryptors (the synchronous version skipped whichever
    // thread it was called on). Started here, before the first class is decrypted.
    start_dr_watchdog();
#if defined(CHIMERA_VMP_BUILD)
    // D: VMProtect's own image CRC. It is only meaningful when the packer enabled "check image
    // CRC"; without a .vmp project that is unverified, so it is logged first and promoted to a hard
    // gate only after a real run shows crc=1.
    {
        const int crc = VMProtectIsValidImageCRC();
        g_vmp_image_crc = crc;
        std::fprintf(stderr, "[chimera-native] vmp image crc=%d\n", crc);
        std::fflush(stderr);
    }
#endif
    // P2-4: the VM verdict is now part of the watched set, so patching either function head (for
    // example to `xor eax,eax; ret`) is caught by the periodic integrity check instead of quietly
    // turning the check off.
    watch_function("is_virtual_machine", reinterpret_cast<const void*>(&is_virtual_machine));
    watch_function("nativeIsVirtualMachine", reinterpret_cast<const void*>(
            &Java_dev_chimera_runtime_ChimeraRuntime_nativeIsVirtualMachine));
    // The VM verdict is also consumed inside key derivation, so that branch is the real patch
    // target - watching only the verdict function would leave it unguarded.
    watch_function("nativeDeriveClassKey", reinterpret_cast<const void*>(
            &Java_dev_chimera_runtime_ChimeraRuntime_nativeDeriveClassKey));
    // P1-3: the pinned auth key is a .rdata string, so the code-section snapshot above does not
    // cover it. Re-hash it against the second baked copy: patching the hex string alone (to point
    // the trust anchor at an attacker key) no longer works, because the fingerprint would have to
    // be recomputed and patched too.
    {
        unsigned char pinnedKey[32];
        static const char* expectedFp = CHIMERA_PINNED_AUTH_PUBKEY_FP_HEX;
        if (std::strlen(expectedFp) == 64 && pinned_auth_pubkey(pinnedKey)) {
            unsigned char digest[32];
            SHA256(pinnedKey, sizeof(pinnedKey), digest);
            bool intact = true;
            for (int i = 0; i < 32 && intact; i++) {
                char hex[3];
                std::snprintf(hex, sizeof(hex), "%02x", digest[i]);
                intact = hex[0] == expectedFp[i * 2] && hex[1] == expectedFp[i * 2 + 1];
            }
            if (!intact) {
                std::fprintf(stderr,
                        "[chimera-native] pinned auth key fingerprint mismatch: refusing to load\n");
                std::fflush(stderr);
                note_auth_pub_tamper();
                std::_Exit(4);
            }
        }
    }
    return JNI_VERSION_1_8;
}

}  // extern "C"


// ------------------------------------------------------------------ S5 hidden classes
//
// C-4: no native class definition and no hidden-class registry exports. S1 stores hidden entries
// under their real internal names so the Fabric class loader resolves them by name; the JNI
// DefineClass path and its registry were dead code that only widened the export surface (red line:
// never restore native DefineClass hidden classes). nativeHiddenClassBytesMatch (B6 JVMTI check)
// stays, because the fragment verifier still uses it.

// B1 / C-3: Java-triggered RegisterNatives for sunk method bodies. JNI_OnLoad runs before mod
// classes are visible, so the main entrypoint calls this from the mod class loader and passes its
// own class as the resolution host. Return codes: 0 = every host class bound, >0 = that many host
// groups failed, <0 = nothing bound (fail closed) or -2 = this DLL carries no sink table.
extern "C" JNIEXPORT jint JNICALL
Java_dev_chimera_runtime_ChimeraRuntime_nativeRegisterSinkMethods(JNIEnv* env, jclass clazz) {
#if defined(CHIMERA_SINK_EXTERNAL_JNI_ONLOAD)
    return chimera_sink_register_all_with_host(env, clazz);
#else
    (void) env;
    (void) clazz;
    return -2;
#endif
}


// ------------------------------------------------------------------ v4 licensing, native-only
//
// The v4 handshake keeps every secret inside this module: the client X25519 private key and the
// server signature are only used here, and the unwrapped ResourceKey goes straight into the
// protected handle table. Java sees a public key, a nonce and a handle id; it can neither forge a
// decision nor read the key.

namespace {
unsigned char g_v4_priv[32];
unsigned char g_v4_pub[32];
unsigned char g_v4_nonce[16];
char g_v4_pub_b64[64];
char g_v4_nonce_hex[40];
uint64_t g_v4_begin_ms = 0;
bool g_v4_ready = false;
constexpr uint64_t kV4AttemptTtlMs = 10 * 60 * 1000;

// Client key persistence (restart without re-activation).
//
// The server binds a v4 session to the client X25519 public key captured at activation, so the
// client must present the *same* key pair on every later heartbeat. g_v4_sealed holds that key
// pair in DPAPI-sealed form (current Windows user scope) and is the only at-rest representation:
// g_v4_priv exists in plaintext only for the duration of one handshake attempt. Java can move the
// blob between processes but can neither read nor mint one, because CryptProtectData's master key
// is per-user (and per-machine, via the user's DPAPI master key files).
std::vector<unsigned char> g_v4_sealed;
bool g_v4_key_ready = false;
// Fixed DPAPI entropy: a blob produced by another application (or another Chimera build) cannot be
// unprotected here even inside the same user profile.
const unsigned char kV4DpapiEntropy[] = "chimera/v1/v4/client-key/dpapi";

bool v4_contains(const std::vector<unsigned char>& haystack,
                 const unsigned char* needle, size_t needle_len) {
    if (needle_len == 0 || haystack.size() < needle_len) return false;
    for (size_t i = 0; i + needle_len <= haystack.size(); i++) {
        if (std::memcmp(haystack.data() + i, needle, needle_len) == 0) return true;
    }
    return false;
}

// DPAPI seal. Deliberately no CRYPTPROTECT_LOCAL_MACHINE: user scope is what makes the blob
// unusable for another Windows account, and the per-user master key makes it unusable on another
// machine (roaming profiles aside, where the same user is the same principal).
bool v4_dpapi_protect(const unsigned char* data, size_t len, std::vector<unsigned char>& out) {
    out.clear();
    if (data == nullptr || len == 0) return false;
    DATA_BLOB plain;
    plain.pbData = const_cast<BYTE*>(data);
    plain.cbData = static_cast<DWORD>(len);
    DATA_BLOB entropy;
    entropy.pbData = const_cast<BYTE*>(kV4DpapiEntropy);
    entropy.cbData = static_cast<DWORD>(sizeof(kV4DpapiEntropy) - 1);
    DATA_BLOB sealed;
    std::memset(&sealed, 0, sizeof(sealed));
    if (!CryptProtectData(&plain, nullptr, &entropy, nullptr, nullptr,
            CRYPTPROTECT_UI_FORBIDDEN, &sealed)) {
        return false;
    }
    if (sealed.pbData == nullptr || sealed.cbData == 0) {
        if (sealed.pbData != nullptr) LocalFree(sealed.pbData);
        return false;
    }
    out.assign(sealed.pbData, sealed.pbData + sealed.cbData);
    LocalFree(sealed.pbData);
    return true;
}

// DPAPI unseal into a fixed 32-byte buffer. Fails for another user/machine, for a truncated or
// tampered blob, and for a blob protected with different entropy.
bool v4_dpapi_unprotect(const unsigned char* blob, size_t len, unsigned char out[32]) {
    if (blob == nullptr || len == 0 || len > (64 * 1024)) return false;
    DATA_BLOB sealed;
    sealed.pbData = const_cast<BYTE*>(blob);
    sealed.cbData = static_cast<DWORD>(len);
    DATA_BLOB entropy;
    entropy.pbData = const_cast<BYTE*>(kV4DpapiEntropy);
    entropy.cbData = static_cast<DWORD>(sizeof(kV4DpapiEntropy) - 1);
    DATA_BLOB plain;
    std::memset(&plain, 0, sizeof(plain));
    if (!CryptUnprotectData(&sealed, nullptr, &entropy, nullptr, nullptr,
            CRYPTPROTECT_UI_FORBIDDEN, &plain)) {
        return false;
    }
    const bool ok = plain.pbData != nullptr && plain.cbData == 32;
    if (ok) std::memcpy(out, plain.pbData, 32);
    if (plain.pbData != nullptr) {
        SecureZeroMemory(plain.pbData, plain.cbData);
        LocalFree(plain.pbData);
    }
    return ok;
}

// Recomputes g_v4_pub / g_v4_pub_b64 from g_v4_priv (the wire form is the base64 raw public key).
bool v4_publish_public_key() {
    EVP_PKEY* key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, g_v4_priv, 32);
    bool ok = key != nullptr;
    if (ok) {
        size_t len = 32;
        ok = EVP_PKEY_get_raw_public_key(key, g_v4_pub, &len) == 1 && len == 32;
    }
    if (key != nullptr) EVP_PKEY_free(key);
    if (!ok) {
        secure_wipe(g_v4_pub, sizeof(g_v4_pub));
        return false;
    }
    std::memset(g_v4_pub_b64, 0, sizeof(g_v4_pub_b64));
    return EVP_EncodeBlock(reinterpret_cast<unsigned char*>(g_v4_pub_b64), g_v4_pub, 32) > 0;
}

// Installs a sealed blob as the live key pair. Never generates a replacement key.
bool v4_key_from_blob(const std::vector<unsigned char>& blob) {
    if (blob.empty()) return false;
    unsigned char priv[32];
    if (!v4_dpapi_unprotect(blob.data(), blob.size(), priv)) {
        secure_wipe(priv, sizeof(priv));
        return false;
    }
    std::memcpy(g_v4_priv, priv, 32);
    secure_wipe(priv, sizeof(priv));
    if (!v4_publish_public_key()) {
        secure_wipe(g_v4_priv, sizeof(g_v4_priv));
        return false;
    }
    g_v4_key_ready = true;
    return true;
}

bool v4_key_from_sealed() {
    return v4_key_from_blob(g_v4_sealed);
}

// Seals the live key pair for persistence. Idempotent: the first blob wins, so a re-activation in
// the same process cannot rotate the identity the server already bound the session to.
bool v4_seal_current_key() {
    if (!g_v4_sealed.empty()) return true;
    if (!g_v4_key_ready) return false;
    std::vector<unsigned char> sealed;
    if (!v4_dpapi_protect(g_v4_priv, sizeof(g_v4_priv), sealed)) return false;
    g_v4_sealed.swap(sealed);
    return true;
}

// Drops the plaintext copy. The sealed blob (if any) survives, so the next attempt reuses the
// same key pair without keeping a readable private key resident.
void v4_clear_live_key() {
    secure_wipe(g_v4_priv, sizeof(g_v4_priv));
    g_v4_key_ready = false;
    g_v4_ready = false;
}
}  // namespace

static void s5_log_key_fingerprint(const char* label, const unsigned char* key) {
#if !defined(CHIMERA_DEV_BUILD)
    // Release: never write anything derived from the ResourceKey to disk. This wrote
    // SHA256(ResourceKey)[0..8] to %USERPROFILE%\.chimera\v4-key-diag.log on every activation and
    // every heartbeat - an offline oracle for "is this the key?", left behind by a debugging
    // session (red team round 4). A truncated hash is still key material.
    (void) label;
    (void) key;
    return;
#else
    char path[MAX_PATH * 2];
    const char* home = getenv("USERPROFILE");
    if (home == nullptr) return;
    std::snprintf(path, sizeof(path), "%s\\.chimera\\v4-key-diag.log", home);
    FILE* file = nullptr;
    if (fopen_s(&file, path, "a") != 0 || file == nullptr) return;
    unsigned char digest[32];
    SHA256(key, 32, digest);
    std::fprintf(file, "%s ", label);
    for (int i = 0; i < 8; i++) std::fprintf(file, "%02x", digest[i]);
    std::fprintf(file, "\n");
    fclose(file);
#endif
}

extern "C" JNIEXPORT jint JNICALL
Java_dev_chimera_runtime_ChimeraRuntime_nativeAuthV4Begin(JNIEnv* env, jclass, jbyteArray out) {
    CHIMERA_VMP_BEGIN("chimera.auth.v4.begin");
    ensure_lock();
    LockGuard guard;
    if (out == nullptr || env->GetArrayLength(out) < 48) return -1;
    if (!code_section_intact()) return -2;
    if (!g_v4_key_ready) {
        if (!g_v4_sealed.empty()) {
            // A persisted key exists but cannot be unsealed (other Windows user/machine, tampered
            // blob, lost DPAPI master key): fail closed. Falling back to keygen would silently
            // rotate the identity the server bound the session to, which the server rejects later
            // with 403 E_KEY_MISMATCH instead of a clear "re-activate" signal.
            if (!v4_key_from_sealed()) return -6;
        } else {
            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
            EVP_PKEY* key = nullptr;
            bool ok = ctx != nullptr && EVP_PKEY_keygen_init(ctx) == 1
                    && EVP_PKEY_keygen(ctx, &key) == 1 && key != nullptr;
            if (ok) {
                size_t len = 32;
                ok = EVP_PKEY_get_raw_private_key(key, g_v4_priv, &len) == 1 && len == 32;
                len = 32;
                ok = ok && EVP_PKEY_get_raw_public_key(key, g_v4_pub, &len) == 1 && len == 32;
            }
            if (key != nullptr) EVP_PKEY_free(key);
            if (ctx != nullptr) EVP_PKEY_CTX_free(ctx);
            if (!ok) {
                secure_wipe(g_v4_priv, sizeof(g_v4_priv));
                return -3;
            }
            g_v4_key_ready = true;
        }
    }
    if (RAND_bytes(g_v4_nonce, sizeof(g_v4_nonce)) != 1) {
        secure_wipe(g_v4_priv, sizeof(g_v4_priv));
        g_v4_key_ready = false;
        return -4;
    }
    std::memset(g_v4_pub_b64, 0, sizeof(g_v4_pub_b64));
    std::memset(g_v4_nonce_hex, 0, sizeof(g_v4_nonce_hex));
    if (EVP_EncodeBlock(reinterpret_cast<unsigned char*>(g_v4_pub_b64), g_v4_pub, 32) <= 0) {
        return -5;
    }
    static const char* kHex = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(g_v4_nonce); i++) {
        g_v4_nonce_hex[i * 2] = kHex[(g_v4_nonce[i] >> 4) & 0xF];
        g_v4_nonce_hex[i * 2 + 1] = kHex[g_v4_nonce[i] & 0xF];
    }
    unsigned char out_bytes[48];
    std::memcpy(out_bytes, g_v4_pub, 32);
    std::memcpy(out_bytes + 32, g_v4_nonce, 16);
    env->SetByteArrayRegion(out, 0, 48, reinterpret_cast<const jbyte*>(out_bytes));
    g_v4_begin_ms = GetTickCount64();
    g_v4_ready = true;
    CHIMERA_VMP_END();
    return 0;
}

extern "C" JNIEXPORT jlong JNICALL
Java_dev_chimera_runtime_ChimeraRuntime_nativeAuthV4Finish(
        JNIEnv* env, jclass, jbyteArray canonical, jbyteArray signature,
        jbyteArray server_pub, jbyteArray envelope, jbyteArray account, jbyteArray hwid) {
    CHIMERA_VMP_BEGIN("chimera.auth.v4.finish");
    ensure_lock();
    LockGuard guard;
    if (!code_section_intact() || should_poison()) return -1;
    if (!g_v4_ready || GetTickCount64() - g_v4_begin_ms > kV4AttemptTtlMs) return -2;
    if (canonical == nullptr || signature == nullptr || server_pub == nullptr
            || envelope == nullptr || account == nullptr || hwid == nullptr) {
        return -3;
    }
    auto read = [&](jbyteArray array, std::vector<unsigned char>& out) -> bool {
        const jsize len = env->GetArrayLength(array);
        if (len <= 0 || len > (64 * 1024)) return false;
        out.resize(static_cast<size_t>(len));
        env->GetByteArrayRegion(array, 0, len, reinterpret_cast<jbyte*>(out.data()));
        return true;
    };
    std::vector<unsigned char> canonical_bytes, signature_bytes, server_pub_bytes;
    std::vector<unsigned char> envelope_bytes, account_bytes, hwid_bytes;
    if (!read(canonical, canonical_bytes) || !read(signature, signature_bytes)
            || !read(server_pub, server_pub_bytes) || !read(envelope, envelope_bytes)
            || !read(account, account_bytes) || !read(hwid, hwid_bytes)) {
        return -4;
    }
    if (server_pub_bytes.size() != 32 || signature_bytes.size() != 64
            || envelope_bytes.size() != 60) {
        return -5;
    }
    // The signature must cover this attempt's public key and nonce, and the pinned server key must
    // sign it; a replayed or redirected response fails here.
    // The canonical transcript carries the base64 public key and the hex nonce (wire form), so
    // bind the signed message to this attempt by searching exactly those strings.
    if (!v4_contains(canonical_bytes,
                reinterpret_cast<const unsigned char*>(g_v4_pub_b64),
                std::strlen(g_v4_pub_b64))
            || !v4_contains(canonical_bytes,
                reinterpret_cast<const unsigned char*>(g_v4_nonce_hex),
                std::strlen(g_v4_nonce_hex))) {
        return -6;
    }
    if (!ed25519_verify_independent(canonical_bytes.data(), canonical_bytes.size(),
            signature_bytes.data(), signature_bytes.size())) {
        return -7;
    }
    unsigned char shared[64];
    size_t shared_len = sizeof(shared);
    if (!x25519_shared(g_v4_priv, server_pub_bytes.data(), shared, &shared_len)
            || shared_len != 32) {
        return -8;
    }
    unsigned char wrap_key[32];
    const unsigned char info[] = "chimera/v1/v4/ck";
    // Server side uses the client_nonce *string* (lowercase hex) as HKDF salt, not the raw bytes.
    if (!hkdf_sha256(shared, shared_len,
            reinterpret_cast<const unsigned char*>(g_v4_nonce_hex),
            std::strlen(g_v4_nonce_hex),
            info, sizeof(info) - 1, wrap_key, sizeof(wrap_key))) {
        return -9;
    }
    std::string aad = "chimera/v1/v4/ck|";
    aad.append(reinterpret_cast<const char*>(account_bytes.data()), account_bytes.size());
    aad.push_back('|');
    aad.append(reinterpret_cast<const char*>(hwid_bytes.data()), hwid_bytes.size());
    unsigned char resource_key[32];
    size_t resource_len = sizeof(resource_key);
    const bool unwrapped = aes_gcm_decrypt(wrap_key, envelope_bytes.data(), 12,
            envelope_bytes.data() + 12, 32, envelope_bytes.data() + 44, 16,
            reinterpret_cast<const unsigned char*>(aad.data()), aad.size(),
            resource_key, &resource_len) && resource_len == 32;
    secure_wipe(shared, sizeof(shared));
    secure_wipe(wrap_key, sizeof(wrap_key));
    if (!unwrapped) {
        secure_wipe(resource_key, sizeof(resource_key));
        secure_wipe(g_v4_priv, sizeof(g_v4_priv));
        g_v4_key_ready = false;
        g_v4_ready = false;
        return -10;
    }
    HandleSlot* slot = nullptr;
    for (size_t i = 0; i < kMaxHandles; i++) {
        if (g_handles[i].state == kHandleFree) {
            slot = &g_handles[i];
            break;
        }
    }
    if (slot == nullptr) {
        secure_wipe(resource_key, sizeof(resource_key));
        return -11;
    }
    wipe_slot_locked(*slot);
    std::memcpy(slot->key, resource_key, 32);  // placeholder, keys are wiped below
    seal_slot_key(*slot, resource_key);
    std::memcpy(slot->nonce, g_v4_nonce, 16);
    const size_t transcript_len = canonical_bytes.size() < sizeof(slot->transcript)
            ? canonical_bytes.size() : sizeof(slot->transcript);
    std::memcpy(slot->transcript, canonical_bytes.data(), transcript_len);
    slot->transcript_len = static_cast<uint16_t>(transcript_len);
    std::memcpy(slot->signature, signature_bytes.data(), 64);
    slot->verify_result = 1;
    slot->resource_key_set = 1;
    // Layer 2: re-install the CNG class key for this (possibly rotated) ResourceKey, so the handle
    // keeps matching the ciphertext in the jar.
    if (!install_class_key(*slot)) {
        secure_wipe(resource_key, sizeof(resource_key));
        return -11;
    }
    slot->created = GetTickCount64();
    slot->last_used = slot->created;
    slot->state = kHandleValid;
    slot->handle = random_u64() & 0x7fffffffffffffffULL;
    if (slot->handle == 0) slot->handle = 1;
    secure_wipe(resource_key, sizeof(resource_key));
    // Seal the key pair for the next launch/heartbeat before dropping the plaintext copy: the
    // server pinned this public key at activation, so every later handshake must reuse it.
    v4_seal_current_key();
    v4_clear_live_key();
    CHIMERA_VMP_END();
    return static_cast<jlong>(slot->handle);
}

extern "C" JNIEXPORT jint JNICALL
Java_dev_chimera_runtime_ChimeraRuntime_nativeAuthV4Status(JNIEnv*, jclass, jlong handle) {
    CHIMERA_VMP_BEGIN("chimera.auth.v4.status");
    ensure_lock();
    LockGuard guard;
    if (!code_section_intact() || should_poison() || handle == 0) return 0;
    const uint64_t now = GetTickCount64();
    for (size_t i = 0; i < kMaxHandles; i++) {
        HandleSlot& slot = g_handles[i];
        if (slot.state == kHandleFree || slot.handle != static_cast<uint64_t>(handle)) continue;
        if (slot_expired_locked(slot, now)) return 0;
        slot.last_used = now;
        CHIMERA_VMP_END();
        return slot.state == kHandleValid && slot.resource_key_set == 1 ? 1 : 0;
    }
    CHIMERA_VMP_END();
    return 0;
}


// Client key persistence, native half. Java only ever handles an opaque DPAPI blob: the private key
// is never returned, and a blob handed back in cannot be read by Java either.
//
// Failure contract: nativeSealClientKey returns null (no key, DPAPI error, poisoned process) and
// nativeUnsealClientKey returns false (wrong Windows user/machine, tampered or truncated blob,
// different entropy). Neither call ever generates a replacement key - a fresh key would change the
// identity the server bound the session to, which must surface as "re-activate", not as a silent
// rotation.
extern "C" JNIEXPORT jbyteArray JNICALL
Java_dev_chimera_runtime_ChimeraRuntime_nativeSealClientKey(JNIEnv* env, jclass) {
    CHIMERA_VMP_BEGIN("chimera.auth.v4.seal");
    ensure_lock();
    LockGuard guard;
    if (!code_section_intact() || should_poison()) return nullptr;
    if (!v4_seal_current_key()) return nullptr;
    if (g_v4_sealed.empty() || g_v4_sealed.size() > (64 * 1024)) return nullptr;
    const jsize len = static_cast<jsize>(g_v4_sealed.size());
    jbyteArray out = env->NewByteArray(len);
    if (out == nullptr) return nullptr;
    env->SetByteArrayRegion(out, 0, len, reinterpret_cast<const jbyte*>(g_v4_sealed.data()));
    CHIMERA_VMP_END();
    return out;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_dev_chimera_runtime_ChimeraRuntime_nativeUnsealClientKey(
        JNIEnv* env, jclass, jbyteArray sealed) {
    CHIMERA_VMP_BEGIN("chimera.auth.v4.unseal");
    ensure_lock();
    LockGuard guard;
    if (sealed == nullptr || !code_section_intact() || should_poison()) return JNI_FALSE;
    const jsize len = env->GetArrayLength(sealed);
    // A real DPAPI blob for 32 bytes is a few hundred bytes; anything outside this window is not
    // a blob this build produced.
    if (len < 64 || len > (64 * 1024)) return JNI_FALSE;
    std::vector<unsigned char> candidate(static_cast<size_t>(len));
    env->GetByteArrayRegion(sealed, 0, len, reinterpret_cast<jbyte*>(candidate.data()));
    if (!v4_key_from_blob(candidate)) return JNI_FALSE;
    g_v4_sealed.swap(candidate);
    g_v4_ready = false;  // no attempt is in flight until the next begin
    CHIMERA_VMP_END();
    return JNI_TRUE;
}


// Heartbeat variant: the response binds client_nonce (not client_ephemeral_pub), so the attempt
// check skips the public-key search; everything else matches AUTH_V4_FINISH.
extern "C" JNIEXPORT jlong JNICALL
Java_dev_chimera_runtime_ChimeraRuntime_nativeAuthV4HeartbeatFinish(
        JNIEnv* env, jclass, jbyteArray canonical, jbyteArray signature,
        jbyteArray server_pub, jbyteArray envelope, jbyteArray account, jbyteArray hwid) {
    CHIMERA_VMP_BEGIN("chimera.auth.v4.heartbeat");
    ensure_lock();
    LockGuard guard;
    if (!code_section_intact() || should_poison()) return -1;
    if (!g_v4_ready || GetTickCount64() - g_v4_begin_ms > kV4AttemptTtlMs) return -2;
    if (canonical == nullptr || signature == nullptr || server_pub == nullptr
            || envelope == nullptr || account == nullptr || hwid == nullptr) {
        return -3;
    }
    auto read = [&](jbyteArray array, std::vector<unsigned char>& out) -> bool {
        const jsize len = env->GetArrayLength(array);
        if (len <= 0 || len > (64 * 1024)) return false;
        out.resize(static_cast<size_t>(len));
        env->GetByteArrayRegion(array, 0, len, reinterpret_cast<jbyte*>(out.data()));
        return true;
    };
    std::vector<unsigned char> canonical_bytes, signature_bytes, server_pub_bytes;
    std::vector<unsigned char> envelope_bytes, account_bytes, hwid_bytes;
    if (!read(canonical, canonical_bytes) || !read(signature, signature_bytes)
            || !read(server_pub, server_pub_bytes) || !read(envelope, envelope_bytes)
            || !read(account, account_bytes) || !read(hwid, hwid_bytes)) {
        return -4;
    }
    if (server_pub_bytes.size() != 32 || signature_bytes.size() != 64
            || envelope_bytes.size() != 60) {
        return -5;
    }
    if (!v4_contains(canonical_bytes,
                reinterpret_cast<const unsigned char*>(g_v4_nonce_hex),
                std::strlen(g_v4_nonce_hex))) {
        return -6;
    }
    if (!ed25519_verify_independent(canonical_bytes.data(), canonical_bytes.size(),
            signature_bytes.data(), signature_bytes.size())) {
        return -7;
    }
    unsigned char shared[64];
    size_t shared_len = sizeof(shared);
    if (!x25519_shared(g_v4_priv, server_pub_bytes.data(), shared, &shared_len)
            || shared_len != 32) {
        return -8;
    }
    unsigned char wrap_key[32];
    const unsigned char info[] = "chimera/v1/v4/ck";
    if (!hkdf_sha256(shared, shared_len,
            reinterpret_cast<const unsigned char*>(g_v4_nonce_hex),
            std::strlen(g_v4_nonce_hex),
            info, sizeof(info) - 1, wrap_key, sizeof(wrap_key))) {
        return -9;
    }
    std::string aad = "chimera/v1/v4/ck|";
    aad.append(reinterpret_cast<const char*>(account_bytes.data()), account_bytes.size());
    aad.push_back('|');
    aad.append(reinterpret_cast<const char*>(hwid_bytes.data()), hwid_bytes.size());
    unsigned char resource_key[32];
    size_t resource_len = sizeof(resource_key);
    const bool unwrapped = aes_gcm_decrypt(wrap_key, envelope_bytes.data(), 12,
            envelope_bytes.data() + 12, 32, envelope_bytes.data() + 44, 16,
            reinterpret_cast<const unsigned char*>(aad.data()), aad.size(),
            resource_key, &resource_len) && resource_len == 32;
    secure_wipe(shared, sizeof(shared));
    secure_wipe(wrap_key, sizeof(wrap_key));
    if (!unwrapped) {
        secure_wipe(resource_key, sizeof(resource_key));
        secure_wipe(g_v4_priv, sizeof(g_v4_priv));
        g_v4_key_ready = false;
        g_v4_ready = false;
        return -10;
    }
    // Red team round 4 (source audit): this used to scan for kHandleFree only. Every heartbeat
    // allocates a fresh slot and nothing ever freed the previous one, and expired slots keep
    // state==kHandleValid until something wipes them - so with kMaxHandles=64 the table ran dry
    // after ~64 minutes, every heartbeat from then on returned -11, and two consecutive failures
    // make the client halt(4). In other words: every licensed player died after about an hour, and
    // no e2e run (all <=200s) could ever observe it.
    // store_handle_slot_locked() reaps expired slots and falls back to LRU eviction, so the table
    // can no longer run dry; the slot just allocated is by definition the newest, so the live
    // session is never the eviction victim.
    HandleSlot* slot = store_handle_slot_locked(nullptr, nullptr, kHandleFree);
    if (!seal_slot_key(*slot, resource_key)) {
        secure_wipe(resource_key, sizeof(resource_key));
        return -11;
    }
    std::memcpy(slot->nonce, g_v4_nonce, 16);
    const size_t transcript_len = canonical_bytes.size() < sizeof(slot->transcript)
            ? canonical_bytes.size() : sizeof(slot->transcript);
    std::memcpy(slot->transcript, canonical_bytes.data(), transcript_len);
    slot->transcript_len = static_cast<uint16_t>(transcript_len);
    std::memcpy(slot->signature, signature_bytes.data(), 64);
    slot->verify_result = 1;
    slot->resource_key_set = 1;
    // Layer 2: re-install the CNG class key for this (possibly rotated) ResourceKey, so the handle
    // keeps matching the ciphertext in the jar.
    if (!install_class_key(*slot)) {
        secure_wipe(resource_key, sizeof(resource_key));
        return -11;
    }
    slot->created = GetTickCount64();
    slot->last_used = slot->created;
    slot->state = kHandleValid;
    slot->handle = random_u64() & 0x7fffffffffffffffULL;
    if (slot->handle == 0) slot->handle = 1;
    secure_wipe(resource_key, sizeof(resource_key));
    // Seal the key pair for the next launch/heartbeat before dropping the plaintext copy: the
    // server pinned this public key at activation, so every later handshake must reuse it.
    v4_seal_current_key();
    v4_clear_live_key();
    CHIMERA_VMP_END();
    return static_cast<jlong>(slot->handle);
}


// S5: defines every hidden jar entry (NUL/LRM-prefixed names) into the given loader. Java's
// JarFile silently drops such names, so the archive is parsed natively (entries are STORED) and
// each class is registered through JNI DefineClass, mirroring the reference loader design.
namespace {
bool s5_read_whole_file(const char* path, std::vector<unsigned char>& out) {
    out.clear();
    FILE* file = nullptr;
    if (fopen_s(&file, path, "rb") != 0 || file == nullptr) return false;
    fseek(file, 0, SEEK_END);
    const long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    if (size <= 0) {
        fclose(file);
        return false;
    }
    out.resize(static_cast<size_t>(size));
    const size_t read = fread(out.data(), 1, out.size(), file);
    fclose(file);
    return read == out.size();
}

uint32_t s5_le32(const unsigned char* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8)
            | (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

uint16_t s5_le16(const unsigned char* p) {
    return static_cast<uint16_t>(p[0] | (p[1] << 8));
}

bool s5_is_hidden_name(const unsigned char* name, size_t len) {
    if (len == 0) return false;
    if (name[0] == 0x00) return true;
    return len >= 3 && name[0] == 0xE2 && name[1] == 0x80 && name[2] == 0x8E;
}
}  // namespace

extern "C" JNIEXPORT jint JNICALL
Java_dev_chimera_runtime_ChimeraRuntime_nativeDefineHiddenClasses(
        JNIEnv* env, jclass, jobject loader, jbyteArray jar_path) {
    if (env == nullptr || jar_path == nullptr) return -1;
    const jsize path_len = env->GetArrayLength(jar_path);
    if (path_len <= 0 || path_len > 4096) return -2;
    std::vector<char> path(static_cast<size_t>(path_len) + 1, 0);
    env->GetByteArrayRegion(jar_path, 0, path_len, reinterpret_cast<jbyte*>(path.data()));
    std::vector<unsigned char> jar;
    if (!s5_read_whole_file(path.data(), jar)) return -3;
    long eocd = -1;
    for (long i = static_cast<long>(jar.size()) - 22; i >= 0; i--) {
        if (jar[static_cast<size_t>(i)] == 0x50 && jar[static_cast<size_t>(i) + 1] == 0x4B
                && jar[static_cast<size_t>(i) + 2] == 0x05
                && jar[static_cast<size_t>(i) + 3] == 0x06) {
            eocd = i;
            break;
        }
    }
    if (eocd < 0) return -4;
    const uint16_t count = s5_le16(&jar[static_cast<size_t>(eocd) + 10]);
    const uint32_t cd = s5_le32(&jar[static_cast<size_t>(eocd) + 16]);
    if (cd >= jar.size()) return -5;
    struct Pending {
        const unsigned char* data;
        size_t size;
        bool done;
    };
    std::vector<Pending> pending;
    pending.reserve(count);
    size_t pos = cd;
    for (uint16_t i = 0; i < count && pos + 46 <= jar.size(); i++) {
        if (s5_le32(&jar[pos]) != 0x02014B50U) break;
        const uint16_t method = s5_le16(&jar[pos + 10]);
        const uint32_t comp_size = s5_le32(&jar[pos + 20]);
        const uint16_t name_len = s5_le16(&jar[pos + 28]);
        const uint16_t extra_len = s5_le16(&jar[pos + 30]);
        const uint16_t comment_len = s5_le16(&jar[pos + 32]);
        const uint32_t local = s5_le32(&jar[pos + 42]);
        const size_t name_at = pos + 46;
        const bool hidden = name_at + name_len <= jar.size()
                && s5_is_hidden_name(&jar[name_at], name_len);
        pos = name_at + name_len + extra_len + comment_len;
        // `local` is a uint32 read straight out of the archive. `local + 30` was evaluated in 32-bit
        // unsigned arithmetic, so a crafted central directory with local = 0xFFFFFFF0 wrapped the sum
        // to 14, passed this bound check and then read ~4 GB past the buffer. Widen before adding.
        if (!hidden || method != 0
                || static_cast<size_t>(local) + 30 > jar.size()) continue;
        const uint16_t local_name = s5_le16(&jar[local + 26]);
        const uint16_t local_extra = s5_le16(&jar[local + 28]);
        const size_t data_at = static_cast<size_t>(local) + 30 + local_name + local_extra;
        if (data_at + comp_size > jar.size() || comp_size == 0) continue;
        pending.push_back({&jar[data_at], comp_size, false});
    }
    // Classes may reference hidden supertypes that appear later in the archive, so define in
    // several passes until no further progress (JNI DefineClass resolves the superclass eagerly).
    jint defined = 0;
    for (int pass = 0; pass < 4; pass++) {
        bool progress = false;
        for (Pending& item : pending) {
            if (item.done) continue;
            jclass defined_class = static_cast<jclass>(env->DefineClass(
                    nullptr, loader, reinterpret_cast<const jbyte*>(item.data),
                    static_cast<jsize>(item.size)));
            if (defined_class == nullptr) {
                env->ExceptionClear();
                continue;
            }
            env->DeleteLocalRef(defined_class);
            item.done = true;
            progress = true;
            defined++;
        }
        if (!progress) break;
    }
    return defined;
}


// S5 lazy variant: defines exactly one hidden class on demand. The member table resolves classes
// lazily, so eager definition (which can initialise unrelated classes before the license gate)
// is avoided; the entry name is NUL/LRM-prefixed so stripping the markers yields the class path.
extern "C" JNIEXPORT jint JNICALL
Java_dev_chimera_runtime_ChimeraRuntime_nativeDefineHiddenClass(
        JNIEnv* env, jclass, jobject loader, jbyteArray jar_path, jbyteArray internal_name) {
    if (env == nullptr || jar_path == nullptr || internal_name == nullptr) return -1;
    const jsize path_len = env->GetArrayLength(jar_path);
    const jsize name_len = env->GetArrayLength(internal_name);
    if (path_len <= 0 || path_len > 4096 || name_len <= 0 || name_len > 1024) return -2;
    std::vector<char> path(static_cast<size_t>(path_len) + 1, 0);
    env->GetByteArrayRegion(jar_path, 0, path_len, reinterpret_cast<jbyte*>(path.data()));
    std::vector<unsigned char> wanted(static_cast<size_t>(name_len));
    env->GetByteArrayRegion(internal_name, 0, name_len,
            reinterpret_cast<jbyte*>(wanted.data()));
    std::vector<unsigned char> jar;
    if (!s5_read_whole_file(path.data(), jar)) return -3;
    long eocd = -1;
    for (long i = static_cast<long>(jar.size()) - 22; i >= 0; i--) {
        if (jar[static_cast<size_t>(i)] == 0x50 && jar[static_cast<size_t>(i) + 1] == 0x4B
                && jar[static_cast<size_t>(i) + 2] == 0x05
                && jar[static_cast<size_t>(i) + 3] == 0x06) {
            eocd = i;
            break;
        }
    }
    if (eocd < 0) return -4;
    const uint16_t count = s5_le16(&jar[static_cast<size_t>(eocd) + 10]);
    const uint32_t cd = s5_le32(&jar[static_cast<size_t>(eocd) + 16]);
    if (cd >= jar.size()) return -5;
    size_t pos = cd;
    for (uint16_t i = 0; i < count && pos + 46 <= jar.size(); i++) {
        if (s5_le32(&jar[pos]) != 0x02014B50U) break;
        const uint16_t method = s5_le16(&jar[pos + 10]);
        const uint32_t comp_size = s5_le32(&jar[pos + 20]);
        const uint16_t name_len = s5_le16(&jar[pos + 28]);
        const uint16_t extra_len = s5_le16(&jar[pos + 30]);
        const uint16_t comment_len = s5_le16(&jar[pos + 32]);
        const uint32_t local = s5_le32(&jar[pos + 42]);
        const size_t name_at = pos + 46;
        pos = name_at + name_len + extra_len + comment_len;
        if (name_at + name_len > jar.size() || method != 0 || local + 30 > jar.size()) continue;
        const unsigned char* name = &jar[name_at];
        if (!s5_is_hidden_name(name, name_len)) continue;
        size_t start = 0;
        if (name[0] == 0x00) {
            start = 1;
        } else {
            start = 3;
        }
        size_t end = name_len;
        // Trailing U+200E markers (E2 80 8E) are part of the invisible suffix.
        while (end >= start + 3 && name[end - 3] == 0xE2 && name[end - 2] == 0x80
                && name[end - 1] == 0x8E) {
            end -= 3;
        }
        if (end - start != wanted.size()) continue;
        if (std::memcmp(name + start, wanted.data(), wanted.size()) != 0) continue;
        const uint16_t local_name = s5_le16(&jar[local + 26]);
        const uint16_t local_extra = s5_le16(&jar[local + 28]);
        const size_t data_at = static_cast<size_t>(local) + 30 + local_name + local_extra;
        if (data_at + comp_size > jar.size() || comp_size == 0) return -6;
        jclass defined_class = static_cast<jclass>(env->DefineClass(
                nullptr, loader, reinterpret_cast<const jbyte*>(&jar[data_at]),
                static_cast<jsize>(comp_size)));
        if (defined_class == nullptr) {
            env->ExceptionClear();
            return 0;
        }
        env->DeleteLocalRef(defined_class);
        return 1;
    }
    return 0;
}


// ------------------------------------------------------------------ JVMTI bootstrap agent
// Fabric applies mixins while Minecraft classes load, before any mod-level hook. The agent serves
// hidden (NUL/LRM) jar entries directly as ClassFileLoadHook class data: when the Knot loader asks
// for a hidden internal name, the bytes come from the agent, so the loader itself defines them and
// resolves super/interfaces in the normal order.
static JavaVM* g_agent_vm = nullptr;
static int g_agent_hook_calls = 0;
static char g_agent_jar_path[MAX_PATH * 2] = {0};
static std::vector<unsigned char> g_agent_jar;

struct AgentHiddenEntry {
    std::string name;
    size_t offset;
    size_t size;
};
static std::vector<AgentHiddenEntry> g_agent_hidden;

static void agent_diag(const char* line) {
    char path[MAX_PATH * 2];
    const char* home = getenv("USERPROFILE");
    if (home == nullptr) return;
    std::snprintf(path, sizeof(path), "%s\\.chimera\\agent-diag.log", home);
    FILE* file = nullptr;
    if (fopen_s(&file, path, "a") != 0 || file == nullptr) return;
    std::fprintf(file, "%s\n", line);
    fclose(file);
}

static void agent_read_jar_option(const char* options) {
    if (options == nullptr) return;
    const char* at = std::strstr(options, "jar=");
    if (at == nullptr) at = std::strstr(options, "jar:");
    if (at == nullptr) return;
    at += 4;
    size_t len = 0;
    while (at[len] != 0 && at[len] != ',' && len < sizeof(g_agent_jar_path) - 1) len++;
    std::memcpy(g_agent_jar_path, at, len);
    g_agent_jar_path[len] = 0;
}

static void agent_load_hidden_entries() {
    g_agent_hidden.clear();
    if (g_agent_jar_path[0] == 0 || !s5_read_whole_file(g_agent_jar_path, g_agent_jar)) return;
    const std::vector<unsigned char>& jar = g_agent_jar;
    long eocd = -1;
    for (long i = static_cast<long>(jar.size()) - 22; i >= 0; i--) {
        if (jar[static_cast<size_t>(i)] == 0x50 && jar[static_cast<size_t>(i) + 1] == 0x4B
                && jar[static_cast<size_t>(i) + 2] == 0x05
                && jar[static_cast<size_t>(i) + 3] == 0x06) { eocd = i; break; }
    }
    if (eocd < 0) { agent_diag("agent: no EOCD"); return; }
    const uint16_t count = s5_le16(&jar[static_cast<size_t>(eocd) + 10]);
    const uint32_t cd = s5_le32(&jar[static_cast<size_t>(eocd) + 16]);
    size_t pos = cd;
    for (uint16_t i = 0; i < count && pos + 46 <= jar.size(); i++) {
        if (s5_le32(&jar[pos]) != 0x02014B50U) break;
        const uint16_t method = s5_le16(&jar[pos + 10]);
        const uint32_t comp_size = s5_le32(&jar[pos + 20]);
        const uint16_t name_len = s5_le16(&jar[pos + 28]);
        const uint16_t extra_len = s5_le16(&jar[pos + 30]);
        const uint16_t comment_len = s5_le16(&jar[pos + 32]);
        const uint32_t local = s5_le32(&jar[pos + 42]);
        const size_t name_at = pos + 46;
        const bool hidden = name_at + name_len <= jar.size()
                && s5_is_hidden_name(&jar[name_at], name_len);
        pos = name_at + name_len + extra_len + comment_len;
        // `local` is a uint32 read straight out of the archive. `local + 30` was evaluated in 32-bit
        // unsigned arithmetic, so a crafted central directory with local = 0xFFFFFFF0 wrapped the sum
        // to 14, passed this bound check and then read ~4 GB past the buffer. Widen before adding.
        if (!hidden || method != 0
                || static_cast<size_t>(local) + 30 > jar.size()) continue;
        const uint16_t local_name = s5_le16(&jar[local + 26]);
        const uint16_t local_extra = s5_le16(&jar[local + 28]);
        const size_t data_at = static_cast<size_t>(local) + 30 + local_name + local_extra;
        if (data_at + comp_size > jar.size() || comp_size == 0) continue;
        const unsigned char* name = &jar[name_at];
        size_t begin = name[0] == 0x00 ? 1 : 3;
        size_t finish = name_len;
        while (finish >= begin + 3 && name[finish - 3] == 0xE2 && name[finish - 2] == 0x80
                && name[finish - 1] == 0x8E) {
            finish -= 3;
        }
        std::string internal(reinterpret_cast<const char*>(name + begin), finish - begin);
        if (internal.size() > 6 && internal.compare(internal.size() - 6, 6, ".class") == 0) {
            internal.resize(internal.size() - 6);
        }
        g_agent_hidden.push_back({internal, data_at, comp_size});
    }
    char summary[64];
    std::snprintf(summary, sizeof(summary), "agent hidden=%zu", g_agent_hidden.size());
    agent_diag(summary);
    for (size_t i = 0; i < g_agent_hidden.size() && i < 3; i++) {
        char hexline[512];
        int at = std::snprintf(hexline, sizeof(hexline), "entry hex=");
        const std::string& entry_name = g_agent_hidden[i].name;
        for (size_t k = 0; k < entry_name.size() && at < static_cast<int>(sizeof(hexline)) - 4;
                k++) {
            at += std::snprintf(hexline + at, sizeof(hexline) - static_cast<size_t>(at), "%02x",
                                static_cast<unsigned char>(entry_name[k]));
        }
        agent_diag(hexline);
    }
}

static void JNICALL agent_class_file_load_hook(jvmtiEnv* jvmti, JNIEnv*, jclass, jobject,
                                               const char* name, jobject, jint,
                                               const unsigned char*, jint* new_len,
                                               unsigned char** new_data) {
    if (name == nullptr || new_data == nullptr || new_len == nullptr
            || g_agent_hidden.empty()) {
        return;
    }
    if (g_agent_hook_calls < 6 && (name[0] == 'p' || name[0] == 'q') && name[1] == '/') {
        g_agent_hook_calls++;
        char message[512];
        int at = std::snprintf(message, sizeof(message), "miss hex=");
        for (size_t i = 0; name[i] != 0 && at < static_cast<int>(sizeof(message)) - 4; i++) {
            at += std::snprintf(message + at, sizeof(message) - static_cast<size_t>(at), "%02x",
                                static_cast<unsigned char>(name[i]));
        }
        agent_diag(message);
    }
    for (const AgentHiddenEntry& entry : g_agent_hidden) {
        if (entry.name != name) continue;
        unsigned char* copy = nullptr;
        if (jvmti->Allocate(static_cast<jlong>(entry.size), &copy) != JVMTI_ERROR_NONE
                || copy == nullptr) {
            return;
        }
        std::memcpy(copy, &g_agent_jar[entry.offset], entry.size);
        *new_data = copy;
        *new_len = static_cast<jint>(entry.size);
        if (g_agent_hook_calls < 4) {
            g_agent_hook_calls++;
            char message[320];
            std::snprintf(message, sizeof(message), "agent supplied %s", name);
            agent_diag(message);
        }
        return;
    }
}

static void JNICALL trace_class_load(jvmtiEnv*, JNIEnv*, jthread, jclass);
static void agent_enable_trace(jvmtiEnv* jvmti);

extern "C" JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM* vm, char* options, void*) {
    g_agent_vm = vm;
    agent_read_jar_option(options);
    if (g_agent_jar_path[0] == 0) return JNI_OK;
    agent_load_hidden_entries();
    jvmtiEnv* jvmti = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(static_cast<void*>(&jvmti)), JVMTI_VERSION_1_2)
            != JNI_OK || jvmti == nullptr) {
        agent_diag("agent: GetEnv failed");
        return JNI_ERR;
    }
    jvmtiCapabilities capabilities = {};
    capabilities.can_generate_all_class_hook_events = 1;
    if (jvmti->AddCapabilities(&capabilities) != JVMTI_ERROR_NONE) {
        agent_diag("agent: AddCapabilities failed");
        return JNI_ERR;
    }
    jvmtiEventCallbacks callbacks = {};
    callbacks.ClassFileLoadHook = &agent_class_file_load_hook;
    callbacks.ClassLoad = &trace_class_load;
    if (jvmti->SetEventCallbacks(&callbacks, sizeof(callbacks)) != JVMTI_ERROR_NONE) {
        agent_diag("agent: SetCallbacks failed");
        return JNI_ERR;
    }
    if (jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_CLASS_FILE_LOAD_HOOK,
                                        nullptr) != JVMTI_ERROR_NONE) {
        agent_diag("agent: class file hook enable failed");
        return JNI_ERR;
    }
    agent_enable_trace(jvmti);
    agent_diag("agent ready");
    return JNI_OK;
}

extern "C" JNIEXPORT jint JNICALL Agent_OnAttach(JavaVM* vm, char*, void*) {
    g_agent_vm = vm;
    return JNI_OK;
}


// S5 tiered define: defines only the hidden entries listed by name (one internal name per line).
// Used by the preLaunch early tier where classes referenced from Mixin/entrypoint bytecode must
// exist before mixin application, while the rest is defined after Bootstrap.
namespace {
bool s5_strip_hidden_entry(const unsigned char* name, size_t len, std::string& out) {
    if (len == 0) return false;
    size_t begin = 0;
    if (name[0] == 0x00) {
        begin = 1;
    } else if (len >= 3 && name[0] == 0xE2 && name[1] == 0x80 && name[2] == 0x8E) {
        begin = 3;
    } else {
        return false;
    }
    size_t end = len;
    auto strip_tail = [&]() {
        while (end >= begin + 3) {
            const unsigned char a = name[end - 3];
            const unsigned char b = name[end - 2];
            const unsigned char c = name[end - 1];
            const bool marker = (a == 0xE2 && b == 0x80 && (c == 0x8E || c == 0x8F))
                    || (a == 0xE2 && b == 0x81 && c == 0xA0);
            if (!marker) break;
            end -= 3;
        }
    };
    strip_tail();
    if (end >= begin + 6 && std::memcmp(name + end - 6, ".class", 6) == 0) {
        end -= 6;
        strip_tail();
    }
    out.assign(reinterpret_cast<const char*>(name + begin), end - begin);
    return !out.empty();
}
}  // namespace

extern "C" JNIEXPORT jint JNICALL
Java_dev_chimera_runtime_ChimeraRuntime_nativeDefineHiddenClassesSubset(
        JNIEnv* env, jclass, jobject loader, jbyteArray jar_path, jbyteArray names) {
    if (env == nullptr || jar_path == nullptr || names == nullptr) return -1;
    const jsize path_len = env->GetArrayLength(jar_path);
    const jsize names_len = env->GetArrayLength(names);
    if (path_len <= 0 || path_len > 4096 || names_len <= 0) return -2;
    std::vector<char> path(static_cast<size_t>(path_len) + 1, 0);
    env->GetByteArrayRegion(jar_path, 0, path_len, reinterpret_cast<jbyte*>(path.data()));
    std::vector<unsigned char> wanted(static_cast<size_t>(names_len));
    env->GetByteArrayRegion(names, 0, names_len, reinterpret_cast<jbyte*>(wanted.data()));
    std::vector<unsigned char> jar;
    if (!s5_read_whole_file(path.data(), jar)) return -3;
    long eocd = -1;
    for (long i = static_cast<long>(jar.size()) - 22; i >= 0; i--) {
        if (jar[static_cast<size_t>(i)] == 0x50 && jar[static_cast<size_t>(i) + 1] == 0x4B
                && jar[static_cast<size_t>(i) + 2] == 0x05
                && jar[static_cast<size_t>(i) + 3] == 0x06) { eocd = i; break; }
    }
    if (eocd < 0) return -4;
    const uint16_t count = s5_le16(&jar[static_cast<size_t>(eocd) + 10]);
    const uint32_t cd = s5_le32(&jar[static_cast<size_t>(eocd) + 16]);
    if (cd >= jar.size()) return -5;
    struct Entry { const unsigned char* data; size_t size; bool done; };
    std::vector<Entry> entries;
    size_t pos = cd;
    for (uint16_t i = 0; i < count && pos + 46 <= jar.size(); i++) {
        if (s5_le32(&jar[pos]) != 0x02014B50U) break;
        const uint16_t method = s5_le16(&jar[pos + 10]);
        const uint32_t comp_size = s5_le32(&jar[pos + 20]);
        const uint16_t name_len = s5_le16(&jar[pos + 28]);
        const uint16_t extra_len = s5_le16(&jar[pos + 30]);
        const uint16_t comment_len = s5_le16(&jar[pos + 32]);
        const uint32_t local = s5_le32(&jar[pos + 42]);
        const size_t name_at = pos + 46;
        const size_t name_end = name_at + name_len;
        pos = name_end + extra_len + comment_len;
        if (name_end > jar.size() || method != 0 || local + 30 > jar.size()) continue;
        std::string stripped;
        if (!s5_strip_hidden_entry(&jar[name_at], name_len, stripped)) continue;
        bool requested = false;
        size_t line_start = 0;
        while (line_start < wanted.size() && !requested) {
            size_t line_end = line_start;
            while (line_end < wanted.size() && wanted[line_end] != '\n' && wanted[line_end] != '\r') {
                line_end++;
            }
            if (line_end > line_start) {
                std::string line(reinterpret_cast<const char*>(&wanted[line_start]),
                                 line_end - line_start);
                if (line.size() > 6 && line.compare(line.size() - 6, 6, ".class") == 0) {
                    line.resize(line.size() - 6);
                }
                requested = line == stripped;
            }
            line_start = line_end + 1;
        }
        if (!requested) continue;
        const uint16_t local_name = s5_le16(&jar[local + 26]);
        const uint16_t local_extra = s5_le16(&jar[local + 28]);
        const size_t data_at = static_cast<size_t>(local) + 30 + local_name + local_extra;
        if (data_at + comp_size > jar.size() || comp_size == 0) continue;
        entries.push_back({&jar[data_at], comp_size, false});
    }
    jint defined = 0;
    for (int pass = 0; pass < 4; pass++) {
        bool progress = false;
        for (Entry& entry : entries) {
            if (entry.done) continue;
            jclass defined_class = static_cast<jclass>(env->DefineClass(
                    nullptr, loader, reinterpret_cast<const jbyte*>(entry.data),
                    static_cast<jsize>(entry.size)));
            if (defined_class == nullptr) { env->ExceptionClear(); continue; }
            env->DeleteLocalRef(defined_class);
            entry.done = true;
            progress = true;
            defined++;
        }
        if (!progress) break;
    }
    return defined;
}


// Early-load tracing: records every class loaded by the JVM (JVMTI ClassLoad) plus explicit
// marker lines written from the injected main entrypoint. The build pipeline consumes the class
// list preceding the marker to seed the preLaunch hidden tier for any mod.
static bool g_trace_enabled = false;
static std::mutex g_trace_mutex;

static void trace_append(const char* line) {
    if (!g_trace_enabled) return;
    std::lock_guard<std::mutex> guard(g_trace_mutex);
    char path[MAX_PATH * 2];
    const char* home = getenv("USERPROFILE");
    if (home == nullptr) return;
    std::snprintf(path, sizeof(path), "%s\\.chimera\\early-classes.log", home);
    FILE* file = nullptr;
    if (fopen_s(&file, path, "a") != 0 || file == nullptr) return;
    std::fprintf(file, "%s\n", line);
    fclose(file);
}

static void JNICALL trace_class_load(jvmtiEnv* jvmti, JNIEnv*, jthread, jclass klass) {
    if (!g_trace_enabled || jvmti == nullptr || klass == nullptr) return;
    char* signature = nullptr;
    if (jvmti->GetClassSignature(klass, &signature, nullptr) != JVMTI_ERROR_NONE
            || signature == nullptr) {
        return;
    }
    if (signature[0] == 'L' && signature[1] != '[') {
        size_t len = std::strlen(signature);
        if (len > 2 && signature[len - 1] == ';') {
            std::string internal(signature + 1, len - 2);
            trace_append(internal.c_str());
        }
    }
    jvmti->Deallocate(reinterpret_cast<unsigned char*>(signature));
}

extern "C" JNIEXPORT void JNICALL
Java_dev_chimera_runtime_ChimeraRuntime_nativeTraceMark(JNIEnv*, jclass) {
    trace_append("---MARK---");
}

static void agent_enable_trace(jvmtiEnv* jvmti) {
    g_trace_enabled = true;
    jvmtiError rc = jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_CLASS_LOAD, nullptr);
    char message[96];
    std::snprintf(message, sizeof(message), "agent trace classload rc=%d", static_cast<int>(rc));
    agent_diag(message);
}


// ---- external C ABI (for launcher shells) ----
//
// Pure C exports so an external launcher (e.g. an E-language shell) can drive the v4 licensing
// handshake without any JVM: activation, heartbeat, status query, error text and shutdown.
// Contract:
//   * extern "C" __declspec(dllexport), simple types only, never throws, returns int status codes;
//   * all key material stays inside this DLL (client X25519 private key, unwrapped ResourceKey,
//     bearer token) - the shell only ever sees integer status codes and error strings;
//   * fail-safe: network/verification failure leaves no session behind, and chimera_get_status
//     reflects that;
//   * the v4 wire protocol is identical to the Java client (ChimeraV4Session): same JSON field
//     names, same binary u32be||utf8 canonical transcripts, same HKDF/AES-GCM unwrap.
//
// Error code space (aligned with the Java-side ChimeraActivationPanel.Status / AuthFailure):
//     0  OK / ACTIVATED
//    -1  local crypto/backend failure (keygen, HKDF, AES-GCM)         -> E_STATE
//    -2  bad arguments (null/empty server, account or password)      -> E_STATE
//    -3  HTTP transport failure (server unreachable, timeout)         -> E_NETWORK
//    -4  malformed response body (not the expected flat JSON)         -> E_NETWORK
//    -5  server rejected with E_AUTH (wrong account/password)        -> E_CREDENTIALS
//    -6  server rejected with E_REVOKED / E_BINDING / E_HWID_MISMATCH
//                                                     or device bind -> E_HWID
//    -7  server rejected with E_EXPIRED                               -> E_EXPIRED
//    -8  server rejected with E_CLOCK_ROLLBACK                       -> E_CLOCK_ROLLBACK
//    -9  response signature verification failed (E_SIGNATURE path)    -> E_SIGNATURE
//   -10  ResourceKey unwrap failed                                     -> E_SIGNATURE
//   -11  other server-side error codes (E_RATE_LIMIT, E_REPLAY, ...)  -> E_STATE
//   -12  no session: heartbeat attempted before activate              -> E_STATE
//   -13  anti-tamper trip: code section patched / instrumentation    -> E_STATE
//   -14  client nonce replayed by the server (E_REPLAY on activate)   -> E_STATE
// Status codes (chimera_get_status): 0 = valid session, 1 = no session, 2 = session expired.

#include <wininet.h>

namespace {

// Pinned server Ed25519 public key (base64, raw 32 bytes) - same value the Java client bakes
// into auth.dat. The shell never supplies a key; verification only trusts this constant.
const char* const kExternalPinnedServerPubB64 = "1dKzhiIbxPAnKPhs1rX+G7GgUN+nna9k8MnA8I9kApg=";

// Single static session slot: one launcher process = one activation. The slot holds the v4
// bearer token + sequence for heartbeats and the native handle id of the ResourceKey slot.
struct ExternalSession {
    bool present;
    bool expired;
    uint64_t native_handle;
    char token[128];
    char account[256];
    char hwid[256];
    char server[512];
    uint64_t sequence;
    uint64_t expires_at;  // epoch seconds as reported by the server
};

ExternalSession g_ext_session = {};
CRITICAL_SECTION g_ext_lock;
bool g_ext_lock_ready = false;
bool g_ext_inited = false;

// Server URL of the current session, captured at activate time (empty when no session).
std::string g_ext_server_url;

const std::string& g_ext_session_server() {
    return g_ext_server_url;
}

// Static error buffer: written under g_ext_lock, read without it. Single-slot sessions mean
// at most one writer; a stale read from another thread is acceptable for a launcher use case.
char g_ext_last_error[512] = {0};

void ext_ensure_init() {
    if (!g_ext_lock_ready) {
        InitializeCriticalSection(&g_ext_lock);
        g_ext_lock_ready = true;
    }
    if (!g_ext_inited) {
        // Local, allocation-free OpenSSL init: pools below fall back to EVP_*_new when absent
        // (the pre-config fallback path in ed25519_verify), so a JVM-less process works too.
        OPENSSL_init_crypto(OPENSSL_INIT_NO_ATEXIT, nullptr);
        // B3-1 baseline: a launcher shell has no JVM, so JNI_OnLoad never ran. Snapshot the code
        // section exactly once here (the JNI path is unaffected; init is idempotent and the
        // second call just re-hashes the same bytes into the same baseline).
        init_code_integrity();
        g_ext_inited = true;
    }
}

void ext_set_error(const char* text) {
    if (text == nullptr) return;
    size_t i = 0;
    for (; i < sizeof(g_ext_last_error) - 1 && text[i] != 0; i++) g_ext_last_error[i] = text[i];
    g_ext_last_error[i] = 0;
}

void ext_set_errorf(const char* prefix, const char* detail) {
    if (prefix == nullptr) return;
    size_t i = 0;
    for (; i < sizeof(g_ext_last_error) - 1 && prefix[i] != 0; i++) g_ext_last_error[i] = prefix[i];
    if (detail != nullptr && i < sizeof(g_ext_last_error) - 4) {
        g_ext_last_error[i++] = ':';
        g_ext_last_error[i++] = ' ';
        for (size_t j = 0; i < sizeof(g_ext_last_error) - 1 && detail[j] != 0; j++) {
            g_ext_last_error[i++] = detail[j];
        }
    }
    g_ext_last_error[i] = 0;
}

void ext_clear_session() {
    secure_wipe(&g_ext_session, sizeof(g_ext_session));
    g_ext_session.present = false;
    g_ext_session.expired = false;
    std::string().swap(g_ext_server_url);
}

// ------------------------------------------------------------------ HWID fallback
//
// The Java fallback (ChimeraLicenseBackend.currentHwid) is
//   hex(SHA-256(hostname | os.name | os.arch | user.name)).
// The native port mirrors it with the same separators; os.name on the Sun JDK for Windows is
// "Windows 10"/"Windows 11" and os.arch is "amd64", which we hardcode to stay deterministic.
void ext_default_hwid(char out[65]) {
    char hostname[256] = {0};
    DWORD hostname_len = sizeof(hostname);
    if (GetComputerNameExA(ComputerNameDnsHostname, hostname, &hostname_len) == 0) {
        hostname[0] = 0;
    }
    char username[256] = {0};
    DWORD username_len = sizeof(username);
    if (GetUserNameA(username, &username_len) == 0) {
        username[0] = 0;
    }
    std::string seed = std::string(hostname) + "|Windows 10|amd64|" + std::string(username);
    unsigned char digest[32];
    SHA256(reinterpret_cast<const unsigned char*>(seed.data()), seed.size(), digest);
    static const char* kHex = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[i * 2] = kHex[(digest[i] >> 4) & 0xF];
        out[i * 2 + 1] = kHex[digest[i] & 0xF];
    }
    out[64] = 0;
}

// ------------------------------------------------------------------ canonical transcripts

void ext_transcript_field(std::vector<unsigned char>& out, const std::string& value) {
    const uint32_t len = static_cast<uint32_t>(value.size());
    unsigned char header[4];
    write_u32_be(header, len);
    out.insert(out.end(), header, header + 4);
    out.insert(out.end(), value.begin(), value.end());
}

// Activate-response transcript: domain, "4", then the 12 fields in server order.
std::vector<unsigned char> ext_activate_transcript(const std::string& account,
                                                   const std::string& hwid,
                                                   const std::string& client_pub_b64,
                                                   const std::string& client_nonce_hex) {
    std::vector<unsigned char> out;
    ext_transcript_field(out, "chimera-auth-v4/activate-response");
    ext_transcript_field(out, "4");
    ext_transcript_field(out, account);
    ext_transcript_field(out, hwid);
    ext_transcript_field(out, client_pub_b64);
    ext_transcript_field(out, client_nonce_hex);
    // server_ephemeral_pub, server_nonce, token, sequence, issued_at, expires_at, server_time,
    // resource_ck are appended by the caller once the response fields are known.
    return out;
}

// Heartbeat-response transcript: domain, "4", hwid, client_nonce, SHA256hex(presented token),
// then token/sequence/server_nonce/issued_at/expires_at/server_time/resource_ck/server_pub.
std::vector<unsigned char> ext_heartbeat_transcript(const std::string& hwid,
                                                    const std::string& client_nonce_hex,
                                                    const std::string& presented_token) {
    std::vector<unsigned char> out;
    ext_transcript_field(out, "chimera-auth-v4/heartbeat-response");
    ext_transcript_field(out, "4");
    ext_transcript_field(out, hwid);
    ext_transcript_field(out, client_nonce_hex);
    unsigned char digest[32];
    SHA256(reinterpret_cast<const unsigned char*>(presented_token.data()),
           presented_token.size(), digest);
    static const char* kHex = "0123456789abcdef";
    std::string hash_hex;
    hash_hex.reserve(64);
    for (int i = 0; i < 32; i++) {
        hash_hex.push_back(kHex[(digest[i] >> 4) & 0xF]);
        hash_hex.push_back(kHex[digest[i] & 0xF]);
    }
    ext_transcript_field(out, hash_hex);
    return out;
}

// ------------------------------------------------------------------ minimal flat JSON writer

std::string ext_json_escape(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 8);
    for (char c : value) {
        if (c == '\\' || c == '"') {
            out.push_back('\\');
            out.push_back(c);
        } else {
            out.push_back(c);
        }
    }
    return out;
}

std::string ext_build_activate_body(const std::string& account, const std::string& password,
                                    const std::string& hwid, const std::string& client_pub_b64,
                                    const std::string& client_nonce_hex) {
    std::string body = "{\"v\":4,\"account\":\"" + ext_json_escape(account)
            + "\",\"password\":\"" + ext_json_escape(password)
            + "\",\"hwid\":\"" + ext_json_escape(hwid)
            + "\",\"client_ephemeral_pub\":\"" + client_pub_b64
            + "\",\"client_nonce\":\"" + client_nonce_hex + "\"}";
    return body;
}

std::string ext_build_heartbeat_body(const std::string& hwid, const std::string& token,
                                     uint64_t sequence, const std::string& client_pub_b64,
                                     const std::string& client_nonce_hex) {
    char seq_text[32];
    std::snprintf(seq_text, sizeof(seq_text), "%llu",
                  static_cast<unsigned long long>(sequence));
    std::string body = "{\"v\":4,\"hwid\":\"" + ext_json_escape(hwid)
            + "\",\"token\":\"" + ext_json_escape(token)
            + "\",\"client_nonce\":\"" + client_nonce_hex
            + "\",\"sequence\":" + seq_text
            + ",\"client_ephemeral_pub\":\"" + client_pub_b64 + "\"}";
    return body;
}

// ------------------------------------------------------------------ HTTP POST (WinINet)
//
// Uses explicit HttpOpenRequest/HttpSendRequest (InternetOpenUrl cannot send a POST body).
struct ExtUrlParts {
    const char* scheme;   // "" -> http, "https" -> https
    std::string host;
    INTERNET_PORT port;
    std::string base;    // path prefix, may be empty
};

bool ext_parse_server(const std::string& server, ExtUrlParts& parts) {
    std::string rest = server;
    while (!rest.empty() && (rest.back() == '/' || rest.back() == ' ')) rest.pop_back();
    if (rest.rfind("http://", 0) == 0) {
        parts.scheme = "";
        rest = rest.substr(7);
        parts.port = INTERNET_DEFAULT_HTTP_PORT;
    } else if (rest.rfind("https://", 0) == 0) {
        parts.scheme = "https";
        rest = rest.substr(8);
        parts.port = INTERNET_DEFAULT_HTTPS_PORT;
    } else {
        ext_set_error("unsupported server URL (need http://host:port)");
        return false;
    }
    std::string hostport = rest;
    const size_t slash = rest.find('/');
    if (slash != std::string::npos) {
        hostport = rest.substr(0, slash);
        parts.base = rest.substr(slash + 1);  // stored without leading slash
    } else {
        parts.base = "";
    }
    const size_t colon = hostport.rfind(':');
    if (colon != std::string::npos) {
        const std::string port_text = hostport.substr(colon + 1);
        char* end = nullptr;
        const long parsed = std::strtol(port_text.c_str(), &end, 10);
        if (end == port_text.c_str() || *end != 0 || parsed <= 0 || parsed > 65535) {
            ext_set_error("invalid port in server URL");
            return false;
        }
        parts.port = static_cast<INTERNET_PORT>(parsed);
        hostport = hostport.substr(0, colon);
    }
    if (hostport.empty()) {
        ext_set_error("empty host in server URL");
        return false;
    }
    parts.host = hostport;
    return true;
}

bool ext_http_post(const std::string& server, const std::string& path,
                   const std::string& body, std::string& response) {
    ExtUrlParts parts;
    if (!ext_parse_server(server, parts)) return false;

    HINTERNET internet = InternetOpenA("chimera-launcher/1.0",
                                      INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
    if (internet == nullptr) {
        ext_set_error("WinINet InternetOpenA failed");
        return false;
    }
    const DWORD timeout = 8000;
    InternetSetOptionA(internet, INTERNET_OPTION_CONNECT_TIMEOUT,
                      const_cast<void*>(static_cast<const void*>(&timeout)), sizeof(timeout));
    InternetSetOptionA(internet, INTERNET_OPTION_RECEIVE_TIMEOUT,
                      const_cast<void*>(static_cast<const void*>(&timeout)), sizeof(timeout));
    InternetSetOptionA(internet, INTERNET_OPTION_SEND_TIMEOUT,
                      const_cast<void*>(static_cast<const void*>(&timeout)), sizeof(timeout));

    std::string target = parts.base.empty() ? path : (parts.base + "/" + path);
    if (!target.empty() && target[0] != '/') target.insert(0, "/");
    HINTERNET connection = InternetConnectA(internet, parts.host.c_str(), parts.port,
                                            nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
    bool ok = false;
    if (connection == nullptr) {
        const DWORD inet_error = GetLastError();
        char text[160];
        std::snprintf(text, sizeof(text), "cannot connect to license server (WinINet error %lu)",
                      static_cast<unsigned long>(inet_error));
        ext_set_error(text);
    } else {
        static const char* kAcceptTypes[] = {"application/json", nullptr};
        HINTERNET request = HttpOpenRequestA(connection, "POST", target.c_str(), nullptr,
                                             nullptr, kAcceptTypes,
                                             parts.scheme[0] == 0
                                                     ? 0 : INTERNET_FLAG_SECURE, 0);
        if (request == nullptr) {
            const DWORD inet_error = GetLastError();
            char text[160];
            std::snprintf(text, sizeof(text), "WinINet HttpOpenRequest failed (error %lu)",
                          static_cast<unsigned long>(inet_error));
            ext_set_error(text);
        } else {
            static const char* kHeaders = "Content-Type: application/json\r\n";
            const BOOL sent = HttpSendRequestA(request, kHeaders,
                                               static_cast<DWORD>(std::strlen(kHeaders)),
                                               const_cast<void*>(
                                                       static_cast<const void*>(body.data())),
                                               static_cast<DWORD>(body.size()));
            if (sent != TRUE) {
                const DWORD inet_error = GetLastError();
                char text[160];
                std::snprintf(text, sizeof(text),
                              "license server request failed (WinINet error %lu)",
                              static_cast<unsigned long>(inet_error));
                ext_set_error(text);
            } else {
                response.clear();
                char buffer[8192];
                DWORD read = 0;
                BOOL more = TRUE;
                while (more) {
                    more = InternetReadFile(request, buffer, sizeof(buffer), &read);
                    if (more != TRUE || read == 0) break;
                    response.append(buffer, read);
                }
                ok = !response.empty();
                if (!ok) ext_set_error("empty response body from license server");
            }
            InternetCloseHandle(request);
        }
        InternetCloseHandle(connection);
    }
    InternetCloseHandle(internet);
    return ok;
}

// ------------------------------------------------------------------ server error mapping

int ext_map_server_error(const std::string& code) {
    if (code == "E_AUTH") return -5;                 // wrong account or password
    if (code == "E_REVOKED" || code == "E_BINDING" || code == "E_HWID_MISMATCH"
            || code == "E_DEVICE_LIMIT") return -6;  // account/device binding
    if (code == "E_EXPIRED") return -7;
    if (code == "E_CLOCK_ROLLBACK") return -8;
    if (code == "E_SIGNATURE") return -9;
    if (code == "E_REPLAY") return -14;
    return -11;  // E_RATE_LIMIT / E_VERSION / E_BAD_REQUEST / E_BAD_PUBKEY / anything else
}

// ------------------------------------------------------------------ v4 core handshake
//
// Shared by activate and heartbeat: generate a fresh X25519 pair + 16-byte nonce, then verify
// the server response signature over the canonical transcript and unwrap the ResourceKey into a
// new handle slot. Returns 0 and fills new_handle on success; a negative error code otherwise.
// Mirrors nativeAuthV4Finish/nativeAuthV4HeartbeatFinish but without JNI and without depending
// on the shared v4 attempt globals (this path owns its per-call attempt state).
struct ExtAttempt {
    unsigned char priv[32];
    unsigned char pub[32];
    unsigned char nonce[16];
    char pub_b64[64];
    char nonce_hex[40];
};

bool ext_attempt_begin(ExtAttempt& attempt) {
    secure_wipe(&attempt, sizeof(attempt));
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    EVP_PKEY* key = nullptr;
    const bool generated = ctx != nullptr && EVP_PKEY_keygen_init(ctx) == 1
            && EVP_PKEY_keygen(ctx, &key) == 1 && key != nullptr;
    bool ok = generated;
    if (ok) {
        size_t len = 32;
        ok = EVP_PKEY_get_raw_private_key(key, attempt.priv, &len) == 1 && len == 32;
        len = 32;
        ok = ok && EVP_PKEY_get_raw_public_key(key, attempt.pub, &len) == 1 && len == 32;
    }
    if (key != nullptr) EVP_PKEY_free(key);
    if (ctx != nullptr) EVP_PKEY_CTX_free(ctx);
    if (!ok) {
        secure_wipe(&attempt, sizeof(attempt));
        ext_set_error("X25519 key generation failed");
        return false;
    }
    if (RAND_bytes(attempt.nonce, sizeof(attempt.nonce)) != 1) {
        secure_wipe(&attempt, sizeof(attempt));
        ext_set_error("client nonce generation failed");
        return false;
    }
    if (EVP_EncodeBlock(reinterpret_cast<unsigned char*>(attempt.pub_b64), attempt.pub, 32) <= 0) {
        secure_wipe(&attempt, sizeof(attempt));
        ext_set_error("client public key encoding failed");
        return false;
    }
    static const char* kHex = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(attempt.nonce); i++) {
        attempt.nonce_hex[i * 2] = kHex[(attempt.nonce[i] >> 4) & 0xF];
        attempt.nonce_hex[i * 2 + 1] = kHex[attempt.nonce[i] & 0xF];
    }
    return true;
}

// Unwraps the resource_ck envelope with the attempt's X25519 private key (identical to the JNI
// v4 finish path: HKDF salt = client_nonce hex string, info = "chimera/v1/v4/ck", AAD binds
// account|hwid) and stores the ResourceKey in a fresh handle slot. Verification only trusts the
// compile-time pinned server Ed25519 key; the shell can never substitute its own.
int ext_finish_handshake(const ExtAttempt& attempt, const std::string& server_pub_b64,
                         const std::string& signature_b64, const std::string& resource_ck_b64,
                         const std::string& account, const std::string& hwid,
                         const std::vector<unsigned char>& canonical, uint64_t& new_handle) {
    std::vector<unsigned char> server_pub, signature, envelope;
    if (!b64_decode(server_pub_b64, server_pub) || server_pub.size() != 32) {
        ext_set_error("bad server_ephemeral_pub in response");
        return -4;
    }
    if (!b64_decode(signature_b64, signature) || signature.size() != 64) {
        ext_set_error("bad signature field in response");
        return -4;
    }
    if (!b64_decode(resource_ck_b64, envelope) || envelope.size() != 60) {
        ext_set_error("bad resource_ck field in response");
        return -4;
    }
    std::vector<unsigned char> pinned;
    if (!b64_decode(kExternalPinnedServerPubB64, pinned) || pinned.size() != 32) {
        ext_set_error("pinned server public key is corrupt");
        return -1;
    }
    if (!ed25519_verify_bn(pinned.data(), canonical.data(), canonical.size(),
                           signature.data(), signature.size())) {
        ext_set_error("server response signature verification failed");
        return -9;
    }
    unsigned char shared[64];
    size_t shared_len = sizeof(shared);
    if (!x25519_shared(attempt.priv, server_pub.data(), shared, &shared_len)
            || shared_len != 32) {
        secure_wipe(shared, sizeof(shared));
        ext_set_error("X25519 key agreement failed");
        return -1;
    }
    unsigned char wrap_key[32];
    const unsigned char info[] = "chimera/v1/v4/ck";
    if (!hkdf_sha256(shared, shared_len,
                     reinterpret_cast<const unsigned char*>(attempt.nonce_hex),
                     std::strlen(attempt.nonce_hex),
                     info, sizeof(info) - 1, wrap_key, sizeof(wrap_key))) {
        secure_wipe(shared, sizeof(shared));
        ext_set_error("HKDF key derivation failed");
        return -1;
    }
    std::string aad = "chimera/v1/v4/ck|" + account + "|" + hwid;
    unsigned char resource_key[32];
    size_t resource_len = sizeof(resource_key);
    const bool unwrapped = aes_gcm_decrypt(wrap_key, envelope.data(), 12,
            envelope.data() + 12, 32, envelope.data() + 44, 16,
            reinterpret_cast<const unsigned char*>(aad.data()), aad.size(),
            resource_key, &resource_len) && resource_len == 32;
    secure_wipe(shared, sizeof(shared));
    secure_wipe(wrap_key, sizeof(wrap_key));
    if (!unwrapped) {
        secure_wipe(resource_key, sizeof(resource_key));
        ext_set_error("ResourceKey unwrap failed (envelope did not authenticate)");
        return -10;
    }
    HandleSlot* slot = nullptr;
    for (size_t i = 0; i < kMaxHandles; i++) {
        if (g_handles[i].state == kHandleFree) {
            slot = &g_handles[i];
            break;
        }
    }
    if (slot == nullptr) {
        secure_wipe(resource_key, sizeof(resource_key));
        ext_set_error("native handle table is full");
        return -1;
    }
    wipe_slot_locked(*slot);
    seal_slot_key(*slot, resource_key);
    std::memcpy(slot->nonce, attempt.nonce, 16);
    const size_t transcript_len = canonical.size() < sizeof(slot->transcript)
            ? canonical.size() : sizeof(slot->transcript);
    std::memcpy(slot->transcript, canonical.data(), transcript_len);
    slot->transcript_len = static_cast<uint16_t>(transcript_len);
    std::memcpy(slot->signature, signature.data(), 64);
    slot->verify_result = 1;
    slot->resource_key_set = 1;
    // Layer 2: re-install the CNG class key for this (possibly rotated) ResourceKey, so the handle
    // keeps matching the ciphertext in the jar.
    if (!install_class_key(*slot)) {
        secure_wipe(resource_key, sizeof(resource_key));
        return -11;
    }
    slot->created = GetTickCount64();
    slot->last_used = slot->created;
    slot->state = kHandleValid;
    slot->handle = random_u64() & 0x7fffffffffffffffULL;
    if (slot->handle == 0) slot->handle = 1;
    secure_wipe(resource_key, sizeof(resource_key));
    new_handle = slot->handle;
    return 0;
}

}  // namespace


// ------------------------------------------------------------------ exported C ABI entry points
//
// All five exports are extern "C", never throw, and communicate status via int return codes.
// The error detail for the most recent failure is available through chimera_last_error().
// Note on server URL: activate takes the base server URL; heartbeat reuses the URL captured at
// activate time (stored in g_ext_session.server) so the shell never re-states it.

extern "C" __declspec(dllexport) int chimera_activate(const char* server, const char* account,
                                                     const char* password, const char* hwid) {
    ext_ensure_init();
    ext_set_error("");
    if (server == nullptr || server[0] == 0 || account == nullptr || account[0] == 0
            || password == nullptr || password[0] == 0) {
        ext_set_error("server, account and password must not be empty");
        return -2;
    }
    const std::string server_text(server);
    const std::string account_text(account);
    const std::string password_text(password);
    char hwid_buf[65];
    std::string hwid_text;
    if (hwid != nullptr && hwid[0] != 0) {
        hwid_text = hwid;
    } else {
        ext_default_hwid(hwid_buf);
        hwid_text = hwid_buf;
        if (hwid_text.empty()) {
            ext_set_error("HWID collection failed");
            return -1;
        }
    }

    // A fresh activation always discards any previous session state.
    EnterCriticalSection(&g_ext_lock);
    ext_clear_session();
    LeaveCriticalSection(&g_ext_lock);

    // Anti-tamper gates: identical policy to the JNI path. A patched module or an attached
    // debugger/instrumentation must never establish a session.
    if (!code_section_intact()) {
        ext_set_error("native module integrity check failed");
        return -13;
    }
    if (should_poison()) {
        ext_set_error("instrumentation or debugger detected");
        return -13;
    }

    ExtAttempt attempt;
    if (!ext_attempt_begin(attempt)) {
        secure_wipe(&attempt, sizeof(attempt));
        return -1;
    }

    int status = 0;
    std::string response;
    const std::string body = ext_build_activate_body(account_text, password_text, hwid_text,
                                                     attempt.pub_b64, attempt.nonce_hex);
    uint64_t new_handle = 0;
    do {
        if (!ext_http_post(server_text, "api/v1/license/v4/activate", body, response)) {
            status = -3;
            break;
        }
        std::string error_code;
        if (find_string(response, "error", error_code)) {
            ext_set_errorf("server rejected activation", error_code.c_str());
            status = ext_map_server_error(error_code);
            break;
        }
        std::string server_pub_b64, signature_b64, resource_ck_b64;
        std::string token, server_nonce;
        if (!find_string(response, "server_ephemeral_pub", server_pub_b64)
                || !find_string(response, "signature", signature_b64)
                || !find_string(response, "resource_ck", resource_ck_b64)
                || !find_string(response, "token", token)
                || !find_string(response, "server_nonce", server_nonce)) {
            ext_set_error("activation response is missing required fields");
            status = -4;
            break;
        }
        std::string f_account, f_hwid, f_client_pub, f_client_nonce;
        find_string(response, "account", f_account);
        find_string(response, "hwid", f_hwid);
        find_string(response, "client_ephemeral_pub", f_client_pub);
        find_string(response, "client_nonce", f_client_nonce);
        long long sequence_value = 0;
        long long issued_value = 0;
        long long expires_value = 0;
        long long server_time_value = 0;
        find_long(response, "sequence", sequence_value);
        find_long(response, "issued_at", issued_value);
        find_long(response, "expires_at", expires_value);
        find_long(response, "server_time", server_time_value);

        // Canonical transcript: domain, "4", then the 12 fields in the exact server order.
        std::vector<unsigned char> canonical = ext_activate_transcript(account_text, hwid_text,
                                                                       attempt.pub_b64,
                                                                       attempt.nonce_hex);
        ext_transcript_field(canonical, server_pub_b64);
        ext_transcript_field(canonical, server_nonce);
        ext_transcript_field(canonical, token);
        ext_transcript_field(canonical, std::to_string(sequence_value));
        ext_transcript_field(canonical, std::to_string(issued_value));
        ext_transcript_field(canonical, std::to_string(expires_value));
        ext_transcript_field(canonical, std::to_string(server_time_value));
        ext_transcript_field(canonical, resource_ck_b64);

        status = ext_finish_handshake(attempt, server_pub_b64, signature_b64, resource_ck_b64,
                                      account_text, hwid_text, canonical, new_handle);
        if (status != 0) break;

        EnterCriticalSection(&g_ext_lock);
        g_ext_session.present = true;
        g_ext_session.expired = false;
        g_ext_session.native_handle = new_handle;
        std::snprintf(g_ext_session.token, sizeof(g_ext_session.token), "%s", token.c_str());
        std::snprintf(g_ext_session.account, sizeof(g_ext_session.account), "%s",
                      account_text.c_str());
        std::snprintf(g_ext_session.hwid, sizeof(g_ext_session.hwid), "%s", hwid_text.c_str());
        std::snprintf(g_ext_session.server, sizeof(g_ext_session.server), "%s",
                      server_text.c_str());
        g_ext_session.sequence = static_cast<uint64_t>(sequence_value);
        g_ext_session.expires_at = static_cast<uint64_t>(expires_value);
        g_ext_server_url = server_text;
        LeaveCriticalSection(&g_ext_lock);
    } while (false);

    secure_wipe(&attempt, sizeof(attempt));
    if (status != 0) {
        EnterCriticalSection(&g_ext_lock);
        ext_clear_session();
        LeaveCriticalSection(&g_ext_lock);
    }
    return status;
}

extern "C" __declspec(dllexport) int chimera_heartbeat() {
    ext_ensure_init();
    ext_set_error("");
    if (!code_section_intact()) {
        ext_set_error("native module integrity check failed");
        return -13;
    }
    if (should_poison()) {
        ext_set_error("instrumentation or debugger detected");
        return -13;
    }

    char token[128];
    char account[256];
    char hwid[256];
    uint64_t sequence = 0;
    uint64_t expires_at = 0;
    bool present = false;
    bool expired = false;
    EnterCriticalSection(&g_ext_lock);
    present = g_ext_session.present;
    expired = g_ext_session.expired;
    std::memcpy(token, g_ext_session.token, sizeof(token));
    std::memcpy(account, g_ext_session.account, sizeof(account));
    std::memcpy(hwid, g_ext_session.hwid, sizeof(hwid));
    sequence = g_ext_session.sequence;
    expires_at = g_ext_session.expires_at;
    LeaveCriticalSection(&g_ext_lock);

    if (!present) {
        ext_set_error("no active session: call chimera_activate first");
        return -12;
    }
    if (expired) {
        ext_set_error("session already expired");
        return -7;
    }
    // Local expiry guard: do not present a token the server already considers dead.
    const uint64_t now_epoch = static_cast<uint64_t>(time(nullptr));
    if (expires_at != 0 && now_epoch >= expires_at) {
        EnterCriticalSection(&g_ext_lock);
        g_ext_session.expired = true;
        LeaveCriticalSection(&g_ext_lock);
        ext_set_error("session expired (local clock past expires_at)");
        return -7;
    }

    ExtAttempt attempt;
    if (!ext_attempt_begin(attempt)) {
        secure_wipe(&attempt, sizeof(attempt));
        return -1;
    }

    int status = 0;
    std::string response;
    const std::string presented_token(token);
    const std::string body = ext_build_heartbeat_body(hwid, presented_token, sequence,
                                                      attempt.pub_b64, attempt.nonce_hex);
    uint64_t new_handle = 0;
    do {
        // Heartbeat uses the server captured at activate time; chimera_activate stores it.
        if (!ext_http_post(g_ext_session_server(), "api/v1/license/v4/heartbeat", body,
                           response)) {
            status = -3;
            break;
        }
        std::string error_code;
        if (find_string(response, "error", error_code)) {
            ext_set_errorf("server rejected heartbeat", error_code.c_str());
            status = ext_map_server_error(error_code);
            if (status == -7) {
                EnterCriticalSection(&g_ext_lock);
                g_ext_session.expired = true;
                LeaveCriticalSection(&g_ext_lock);
            }
            break;
        }
        std::string server_pub_b64, signature_b64, resource_ck_b64, new_token, server_nonce;
        if (!find_string(response, "server_ephemeral_pub", server_pub_b64)
                || !find_string(response, "signature", signature_b64)
                || !find_string(response, "resource_ck", resource_ck_b64)
                || !find_string(response, "token", new_token)
                || !find_string(response, "server_nonce", server_nonce)) {
            ext_set_error("heartbeat response is missing required fields");
            status = -4;
            break;
        }
        long long sequence_value = 0;
        long long issued_value = 0;
        long long expires_value = 0;
        long long server_time_value = 0;
        find_long(response, "sequence", sequence_value);
        find_long(response, "issued_at", issued_value);
        find_long(response, "expires_at", expires_value);
        find_long(response, "server_time", server_time_value);

        // Canonical heartbeat transcript: domain, "4", hwid, client_nonce, SHA256hex(old token),
        // then token/sequence/server_nonce/issued_at/expires_at/server_time/resource_ck/server_pub.
        std::vector<unsigned char> canonical = ext_heartbeat_transcript(hwid, attempt.nonce_hex,
                                                                       presented_token);
        ext_transcript_field(canonical, new_token);
        ext_transcript_field(canonical, std::to_string(sequence_value));
        ext_transcript_field(canonical, server_nonce);
        ext_transcript_field(canonical, std::to_string(issued_value));
        ext_transcript_field(canonical, std::to_string(expires_value));
        ext_transcript_field(canonical, std::to_string(server_time_value));
        ext_transcript_field(canonical, resource_ck_b64);
        ext_transcript_field(canonical, server_pub_b64);

        status = ext_finish_handshake(attempt, server_pub_b64, signature_b64, resource_ck_b64,
                                     account, hwid, canonical, new_handle);
        if (status != 0) break;

        EnterCriticalSection(&g_ext_lock);
        g_ext_session.native_handle = new_handle;
        std::snprintf(g_ext_session.token, sizeof(g_ext_session.token), "%s", new_token.c_str());
        g_ext_session.sequence = static_cast<uint64_t>(sequence_value);
        g_ext_session.expires_at = static_cast<uint64_t>(expires_value);
        g_ext_session.present = true;
        g_ext_session.expired = false;
        LeaveCriticalSection(&g_ext_lock);
    } while (false);

    secure_wipe(&attempt, sizeof(attempt));
    if (status == -7 || status == -6 || status == -9 || status == -10) {
        // Expired/revoked/unwrapped-to-a-dead-session: only a fresh activation can recover.
        EnterCriticalSection(&g_ext_lock);
        const bool was_expired = g_ext_session.expired;
        ext_clear_session();
        g_ext_session.expired = was_expired || status == -7;
        LeaveCriticalSection(&g_ext_lock);
    }
    return status;
}

extern "C" __declspec(dllexport) int chimera_get_status() {
    ext_ensure_init();
    EnterCriticalSection(&g_ext_lock);
    const bool present = g_ext_session.present;
    const bool expired = g_ext_session.expired;
    const uint64_t handle = g_ext_session.native_handle;
    const uint64_t expires_at = g_ext_session.expires_at;
    LeaveCriticalSection(&g_ext_lock);
    if (!present) return 1;
    if (expired) return 2;
    // Wall-clock expiry check first: the server may have rotated past our last known state.
    const uint64_t now_epoch = static_cast<uint64_t>(time(nullptr));
    if (expires_at != 0 && now_epoch >= expires_at) {
        EnterCriticalSection(&g_ext_lock);
        g_ext_session.expired = true;
        LeaveCriticalSection(&g_ext_lock);
        return 2;
    }
    if (!code_section_intact()) return 2;  // patched module: never report a usable session
    const uint64_t now = GetTickCount64();
    for (size_t i = 0; i < kMaxHandles; i++) {
        HandleSlot& slot = g_handles[i];
        if (slot.state == kHandleFree || slot.handle != handle) continue;
        if (slot_expired_locked(slot, now)) return 2;
        if (slot.state != kHandleValid || slot.resource_key_set != 1) return 2;
        return 0;
    }
    return 2;  // slot vanished (TTL reaped): treat as expired, fail closed
}

extern "C" __declspec(dllexport) const char* chimera_last_error() {
    ext_ensure_init();
    return g_ext_last_error;
}

extern "C" __declspec(dllexport) int chimera_shutdown() {
    ext_ensure_init();
    ext_set_error("");
    EnterCriticalSection(&g_ext_lock);
    ext_clear_session();
    LeaveCriticalSection(&g_ext_lock);
    return 0;
}
