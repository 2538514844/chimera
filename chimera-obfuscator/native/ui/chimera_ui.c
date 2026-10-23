/*
 * chimera_ui.dll - Chimera Obfuscator UI bridge (Win32, C, no JVM).
 *
 * The E-language window only draws the form; this DLL spawns the Java engine, streams its
 * stdout/stderr, exposes it through a poll API, can cancel the process tree, and computes
 * SHA-256 for the produced jar.
 *
 * All exported strings are UTF-8. Internally everything is converted to UTF-16 for Win32 APIs.
 * Calling convention: __stdcall (x86 exports are aliased to undecorated names by the .def file).
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <wchar.h>

#define CHIMERA_UI_VERSION "1.0.0"
#define MAX_JOBS 4
#define JOB_BUF_LIMIT (8u * 1024u * 1024u)
#define READ_CHUNK 4096u

typedef struct Job {
    int id;
    HANDLE process;
    HANDLE jobObject;
    HANDLE pipeRead;
    HANDLE thread;
    CRITICAL_SECTION lock;
    char* buffer;
    size_t len;
    size_t cap;
    volatile LONG finished;
    DWORD exitCode;
    int used;
} Job;

static Job g_jobs[MAX_JOBS];
static CRITICAL_SECTION g_global;
static INIT_ONCE g_once = INIT_ONCE_STATIC_INIT;
static char g_lastError[1024];

static BOOL CALLBACK init_once(PINIT_ONCE once, PVOID param, PVOID* ctx) {
    (void)once; (void)param; (void)ctx;
    InitializeCriticalSection(&g_global);
    return TRUE;
}

static void ensure_init(void) {
    InitOnceExecuteOnce(&g_once, init_once, NULL, NULL);
}

static void set_error(const char* message) {
    ensure_init();
    EnterCriticalSection(&g_global);
    strncpy(g_lastError, message ? message : "", sizeof(g_lastError) - 1);
    g_lastError[sizeof(g_lastError) - 1] = 0;
    LeaveCriticalSection(&g_global);
}

static void set_error_win32(const char* prefix, DWORD code) {
    char buf[1024];
    _snprintf(buf, sizeof(buf) - 1, "%s (win32=%lu)", prefix ? prefix : "", (unsigned long)code);
    buf[sizeof(buf) - 1] = 0;
    set_error(buf);
}

static wchar_t* utf8_to_wide(const char* text) {
    int need;
    wchar_t* out;
    if (!text) return NULL;
    need = MultiByteToWideChar(CP_UTF8, 0, text, -1, NULL, 0);
    if (need <= 0) return NULL;
    out = (wchar_t*)calloc((size_t)need, sizeof(wchar_t));
    if (!out) return NULL;
    if (MultiByteToWideChar(CP_UTF8, 0, text, -1, out, need) <= 0) {
        free(out);
        return NULL;
    }
    return out;
}

static char* wide_to_utf8(const wchar_t* text) {
    int need;
    char* out;
    if (!text) return NULL;
    need = WideCharToMultiByte(CP_UTF8, 0, text, -1, NULL, 0, NULL, NULL);
    if (need <= 0) return NULL;
    out = (char*)calloc((size_t)need, 1);
    if (!out) return NULL;
    if (WideCharToMultiByte(CP_UTF8, 0, text, -1, out, need, NULL, NULL) <= 0) {
        free(out);
        return NULL;
    }
    return out;
}

static int copy_out(char* out, int cap, const char* text) {
    size_t len;
    if (!out || cap <= 0) return 0;
    if (!text) text = "";
    len = strlen(text);
    if (len >= (size_t)cap) len = (size_t)cap - 1;
    memcpy(out, text, len);
    out[len] = 0;
    return (int)len;
}

/* ---------------------------------------------------------------- SHA-256 */

typedef struct { uint32_t state[8]; uint64_t bitlen; uint8_t data[64]; uint32_t datalen; } SHA256_CTX;

static const uint32_t sha256_k[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

#define ROTR32(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR32(x,2) ^ ROTR32(x,13) ^ ROTR32(x,22))
#define EP1(x) (ROTR32(x,6) ^ ROTR32(x,11) ^ ROTR32(x,25))
#define SIG0(x) (ROTR32(x,7) ^ ROTR32(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTR32(x,17) ^ ROTR32(x,19) ^ ((x) >> 10))

static void sha256_transform(SHA256_CTX* c, const uint8_t* d) {
    uint32_t a,b,cc,dd,e,f,g,h,i,j,t1,t2,m[64];
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = ((uint32_t)d[j] << 24) | ((uint32_t)d[j+1] << 16) | ((uint32_t)d[j+2] << 8) | ((uint32_t)d[j+3]);
    for (; i < 64; ++i) m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
    a = c->state[0]; b = c->state[1]; cc = c->state[2]; dd = c->state[3];
    e = c->state[4]; f = c->state[5]; g = c->state[6]; h = c->state[7];
    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e,f,g) + sha256_k[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,cc);
        h = g; g = f; f = e; e = dd + t1;
        dd = cc; cc = b; b = a; a = t1 + t2;
    }
    c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += dd;
    c->state[4] += e; c->state[5] += f; c->state[6] += g; c->state[7] += h;
}

static void sha256_init(SHA256_CTX* c) {
    c->datalen = 0; c->bitlen = 0;
    c->state[0]=0x6a09e667u; c->state[1]=0xbb67ae85u; c->state[2]=0x3c6ef372u; c->state[3]=0xa54ff53au;
    c->state[4]=0x510e527fu; c->state[5]=0x9b05688cu; c->state[6]=0x1f83d9abu; c->state[7]=0x5be0cd19u;
}

static void sha256_update(SHA256_CTX* c, const uint8_t* data, size_t len) {
    size_t i;
    for (i = 0; i < len; ++i) {
        c->data[c->datalen++] = data[i];
        if (c->datalen == 64) { sha256_transform(c, c->data); c->bitlen += 512; c->datalen = 0; }
    }
}

static void sha256_final(SHA256_CTX* c, uint8_t* hash) {
    uint32_t i = c->datalen;
    c->bitlen += (uint64_t)c->datalen * 8u;
    c->data[i++] = 0x80;
    if (i > 56) { while (i < 64) c->data[i++] = 0; sha256_transform(c, c->data); i = 0; }
    while (i < 56) c->data[i++] = 0;
    for (i = 0; i < 8; ++i) c->data[63 - i] = (uint8_t)(c->bitlen >> (8 * i));
    sha256_transform(c, c->data);
    for (i = 0; i < 8; ++i) {
        uint32_t v = c->state[i];
        hash[i*4+0] = (uint8_t)(v >> 24); hash[i*4+1] = (uint8_t)(v >> 16);
        hash[i*4+2] = (uint8_t)(v >> 8);  hash[i*4+3] = (uint8_t)v;
    }
}

/* ---------------------------------------------------------------- java/job */

static char* find_java_path(const char* explicitPath) {
    wchar_t module[MAX_PATH * 2];
    wchar_t candidate[MAX_PATH * 4];
    DWORD n;
    if (explicitPath && explicitPath[0]) {
        wchar_t* w = utf8_to_wide(explicitPath);
        if (w) {
            if (GetFileAttributesW(w) != INVALID_FILE_ATTRIBUTES) return wide_to_utf8(w);
            free(w);
        }
        return NULL;
    }
    n = GetModuleFileNameW(NULL, module, (DWORD)(sizeof(module) / sizeof(wchar_t)));
    if (n > 0 && n < sizeof(module) / sizeof(wchar_t)) {
        wchar_t* slash = wcsrchr(module, L'\\');
        if (slash) {
            static const wchar_t* rel[] = {
                L"\\jre\\bin\\java.exe", L"\\..\\jre\\bin\\java.exe",
                L"\\java\\bin\\java.exe", L"\\..\\java\\bin\\java.exe"
            };
            size_t k;
            for (k = 0; k < sizeof(rel) / sizeof(rel[0]); ++k) {
                *slash = 0;
                _snwprintf(candidate, sizeof(candidate) / sizeof(wchar_t) - 1, L"%s%s", module, rel[k]);
                candidate[sizeof(candidate) / sizeof(wchar_t) - 1] = 0;
                *slash = L'\\';
                if (GetFileAttributesW(candidate) != INVALID_FILE_ATTRIBUTES) return wide_to_utf8(candidate);
            }
        }
    }
    n = GetEnvironmentVariableW(L"JAVA_HOME", candidate, (DWORD)(sizeof(candidate) / sizeof(wchar_t)));
    if (n > 0 && n < sizeof(candidate) / sizeof(wchar_t)) {
        wcscat(candidate, L"\\bin\\java.exe");
        if (GetFileAttributesW(candidate) != INVALID_FILE_ATTRIBUTES) return wide_to_utf8(candidate);
    }
    n = SearchPathW(NULL, L"java.exe", NULL, (DWORD)(sizeof(candidate) / sizeof(wchar_t)), candidate, NULL);
    if (n > 0) return wide_to_utf8(candidate);
    return NULL;
}

static DWORD WINAPI reader_thread(LPVOID param) {
    Job* job = (Job*)param;
    char chunk[READ_CHUNK];
    DWORD got = 0;
    while (ReadFile(job->pipeRead, chunk, READ_CHUNK, &got, NULL) && got > 0) {
        EnterCriticalSection(&job->lock);
        if (job->len + got + 1 <= JOB_BUF_LIMIT) {
            if (job->len + got + 1 > job->cap) {
                size_t next = job->cap ? job->cap * 2 : 16384;
                char* grown;
                while (next < job->len + got + 1) next *= 2;
                grown = (char*)realloc(job->buffer, next);
                if (grown) { job->buffer = grown; job->cap = next; }
            }
            if (job->buffer && job->len + got + 1 <= job->cap) {
                memcpy(job->buffer + job->len, chunk, got);
                job->len += got;
                job->buffer[job->len] = 0;
            }
        }
        LeaveCriticalSection(&job->lock);
    }
    WaitForSingleObject(job->process, INFINITE);
    GetExitCodeProcess(job->process, &job->exitCode);
    InterlockedExchange(&job->finished, 1);
    CloseHandle(job->pipeRead);
    job->pipeRead = NULL;
    return 0;
}

static Job* job_by_id(int id) {
    int i;
    ensure_init();
    for (i = 0; i < MAX_JOBS; ++i) {
        if (g_jobs[i].used && g_jobs[i].id == id) return &g_jobs[i];
    }
    return NULL;
}

static int utf8_boundary_cut(const char* buf, int len) {
    int i;
    if (len <= 0) return 0;
    for (i = len - 1; i > 0; --i) {
        if ((((unsigned char)buf[i]) & 0xC0) != 0x80) return i;
    }
    return 0;
}

/* ---------------------------------------------------------------- exports */

__declspec(dllexport) int __stdcall chimera_ui_version(char* out, int cap) {
    return copy_out(out, cap, CHIMERA_UI_VERSION);
}

__declspec(dllexport) int __stdcall chimera_ui_find_java(const char* javaPathOrNull, char* outPath, int cap) {
    char* found = find_java_path(javaPathOrNull);
    if (!found) { set_error("java.exe not found (provide javaPath or bundle jre\\bin\\java.exe)"); return 0; }
    copy_out(outPath, cap, found);
    free(found);
    return 1;
}

__declspec(dllexport) int __stdcall chimera_ui_start(const char* engineJar, const char* javaPathOrNull,
                                                     const char* workDirOrNull, const char* engineArgs,
                                                     char* outLine, int cap) {
    Job* job = NULL;
    int slot = -1, i, id = -1;
    char* javaPath;
    wchar_t* wJava = NULL;
    wchar_t* wEngine = NULL;
    wchar_t* wArgs = NULL;
    wchar_t* wWork = NULL;
    wchar_t* cmd = NULL;
    SECURITY_ATTRIBUTES sa;
    HANDLE pipeRead = NULL, pipeWrite = NULL;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    size_t cmdChars;
    int ok = 0;

    ensure_init();
    if (!engineJar || !engineJar[0]) { set_error("engineJar is required"); return -1; }

    javaPath = find_java_path(javaPathOrNull);
    if (!javaPath) { set_error("java.exe not found"); return -2; }
    wJava = utf8_to_wide(javaPath);
    wEngine = utf8_to_wide(engineJar);
    wArgs = (engineArgs && engineArgs[0]) ? utf8_to_wide(engineArgs) : NULL;
    wWork = (workDirOrNull && workDirOrNull[0]) ? utf8_to_wide(workDirOrNull) : NULL;
    free(javaPath);
    if (!wJava || !wEngine) { set_error("path conversion failed"); goto cleanup; }

    cmdChars = wcslen(wJava) + wcslen(wEngine) + (wArgs ? wcslen(wArgs) : 0) + 256;
    cmd = (wchar_t*)calloc(cmdChars, sizeof(wchar_t));
    if (!cmd) { set_error("out of memory"); goto cleanup; }
    _snwprintf(cmd, cmdChars - 1, L"\"%s\" -Dstdout.encoding=UTF-8 -Dstderr.encoding=UTF-8 -Dfile.encoding=UTF-8 -jar \"%s\"%s%s",
               wJava, wEngine, (wArgs && wArgs[0]) ? L" " : L"", (wArgs && wArgs[0]) ? wArgs : L"");
    cmd[cmdChars - 1] = 0;

    EnterCriticalSection(&g_global);
    for (i = 0; i < MAX_JOBS; ++i) {
        if (!g_jobs[i].used) { slot = i; break; }
    }
    LeaveCriticalSection(&g_global);
    if (slot < 0) { set_error("no free job slot (max 4)"); goto cleanup; }

    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    if (!CreatePipe(&pipeRead, &pipeWrite, &sa, 0)) { set_error_win32("CreatePipe", GetLastError()); goto cleanup; }
    SetHandleInformation(pipeRead, HANDLE_FLAG_INHERIT, 0);

    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = pipeWrite;
    si.hStdError = pipeWrite;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    if (!CreateProcessW(NULL, cmd, NULL, NULL, TRUE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW,
                        NULL, wWork, &si, &pi)) {
        set_error_win32("CreateProcess", GetLastError());
        CloseHandle(pipeRead); CloseHandle(pipeWrite);
        goto cleanup;
    }
    CloseHandle(pipeWrite);
    pipeWrite = NULL;

    job = &g_jobs[slot];
    memset(job, 0, sizeof(*job));
    job->process = pi.hProcess;
    job->pipeRead = pipeRead;
    job->exitCode = 0;
    InitializeCriticalSection(&job->lock);
    job->jobObject = CreateJobObjectW(NULL, NULL);
    if (job->jobObject) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info;
        memset(&info, 0, sizeof(info));
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(job->jobObject, JobObjectExtendedLimitInformation, &info, sizeof(info));
        AssignProcessToJobObject(job->jobObject, pi.hProcess);
    }
    EnterCriticalSection(&g_global);
    for (i = 0, id = 1; i < MAX_JOBS; ++i) { if (g_jobs[i].id >= id) id = g_jobs[i].id + 1; }
    EnterCriticalSection(&job->lock);
    job->id = id;
    job->used = 1;
    LeaveCriticalSection(&job->lock);
    LeaveCriticalSection(&g_global);
    job->thread = CreateThread(NULL, 0, reader_thread, job, 0, NULL);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    ok = 1;

cleanup:
    if (!ok && job) {
        job->used = 0;
        if (job->process) CloseHandle(job->process);
        if (job->jobObject) CloseHandle(job->jobObject);
        DeleteCriticalSection(&job->lock);
        if (job->buffer) free(job->buffer);
        memset(job, 0, sizeof(*job));
    }
    if (wJava) free(wJava);
    if (wEngine) free(wEngine);
    if (wArgs) free(wArgs);
    if (wWork) free(wWork);
    if (cmd) free(cmd);
    if (!ok) return -3;
    if (outLine && cap > 0) _snprintf(outLine, (size_t)cap - 1, "{\"job\":%d}", id);
    return id;
}

__declspec(dllexport) int __stdcall chimera_ui_poll(int jobId, char* out, int cap) {
    Job* job = job_by_id(jobId);
    int take = 0, r = 0;
    if (!job) { set_error("unknown job"); return -1; }
    if (!out || cap <= 0) { set_error("bad buffer"); return -1; }
    EnterCriticalSection(&job->lock);
    if (job->len > 0) {
        take = (job->len < (size_t)cap - 1) ? (int)job->len : cap - 1;
        take = utf8_boundary_cut(job->buffer, take);
        if (take <= 0 && (size_t)cap - 1 >= 4) take = (int)((job->len < (size_t)cap - 1) ? job->len : (size_t)cap - 1);
        memcpy(out, job->buffer, (size_t)take);
        out[take] = 0;
        memmove(job->buffer, job->buffer + take, job->len - (size_t)take);
        job->len -= (size_t)take;
        r = 1;
    } else if (InterlockedCompareExchange(&job->finished, 1, 1) == 1) {
        out[0] = 0;
        r = 2;
    } else {
        out[0] = 0;
        r = 0;
    }
    LeaveCriticalSection(&job->lock);
    return r;
}

__declspec(dllexport) int __stdcall chimera_ui_exit_code(int jobId) {
    Job* job = job_by_id(jobId);
    if (!job) return -1;
    if (InterlockedCompareExchange(&job->finished, 1, 1) != 1) return -999;
    return (int)job->exitCode;
}

__declspec(dllexport) int __stdcall chimera_ui_cancel(int jobId) {
    Job* job = job_by_id(jobId);
    if (!job) return 0;
    if (InterlockedCompareExchange(&job->finished, 1, 1) == 1) return 1;
    if (job->jobObject) TerminateJobObject(job->jobObject, 0xFFFFFFFFu);
    else TerminateProcess(job->process, 0xFFFFFFFFu);
    return 1;
}

__declspec(dllexport) int __stdcall chimera_ui_last_error(char* out, int cap) {
    ensure_init();
    EnterCriticalSection(&g_global);
    copy_out(out, cap, g_lastError);
    LeaveCriticalSection(&g_global);
    return 1;
}

__declspec(dllexport) int __stdcall chimera_ui_sha256(const char* pathUtf8, char* outHex, int cap) {
    wchar_t* wPath;
    HANDLE file;
    SHA256_CTX ctx;
    uint8_t hash[32];
    unsigned char buffer[65536];
    DWORD got = 0, i;
    char hex[65];
    static const char* digits = "0123456789abcdef";
    if (!pathUtf8 || !pathUtf8[0]) { set_error("path is required"); return 0; }
    wPath = utf8_to_wide(pathUtf8);
    if (!wPath) { set_error("path conversion failed"); return 0; }
    file = CreateFileW(wPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    free(wPath);
    if (file == INVALID_HANDLE_VALUE) { set_error_win32("open file", GetLastError()); return 0; }
    sha256_init(&ctx);
    while (ReadFile(file, buffer, sizeof(buffer), &got, NULL) && got > 0) sha256_update(&ctx, buffer, got);
    CloseHandle(file);
    sha256_final(&ctx, hash);
    for (i = 0; i < 32; ++i) { hex[i*2] = digits[hash[i] >> 4]; hex[i*2+1] = digits[hash[i] & 0xF]; }
    hex[64] = 0;
    copy_out(outHex, cap, hex);
    return 1;
}

__declspec(dllexport) void __stdcall chimera_ui_shutdown(void) {
    int i;
    ensure_init();
    for (i = 0; i < MAX_JOBS; ++i) {
        Job* job = &g_jobs[i];
        if (!job->used) continue;
        if (job->jobObject) TerminateJobObject(job->jobObject, 0xFFFFFFFFu);
        if (job->process) CloseHandle(job->process);
        if (job->jobObject) CloseHandle(job->jobObject);
        DeleteCriticalSection(&job->lock);
        if (job->buffer) free(job->buffer);
        memset(job, 0, sizeof(*job));
    }
}
