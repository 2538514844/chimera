# Chimera native auth build (M8): statically links OpenSSL into chimera_auth.dll.
#
# Result: one self-contained DLL. No libcrypto-3-x64.dll / libssl-3-x64.dll, no
# libgcc/libstdc++/libwinpthread DLLs next to the game.
#
# Usage (from the repository root):
#   powershell -ExecutionPolicy Bypass -File chimera-obfuscator/scripts/build-native-auth.ps1
#
# Optional parameters:
#   -Configuration <dev|release>  dev = QA hooks + short TTL allowed (tests only, never shipped);
#                                 release = hooks compiled out (default, ships to native/windows-x64)
#   -OpenSslDir <dir>   directory containing include/openssl and lib/libcrypto.a
#                       (default: tools/msys2-mingw64/mingw64, then tools/openssl-static/pkg/mingw64)
#   -Gcc <path>         g++.exe (default: the g++ shipped with -OpenSslDir, then CLion's MinGW)
#   -JavaHome <dir>     JDK with include/jni.h (default: $env:JAVA_HOME, then java.home)
param(
    [string]$OpenSslDir = "",
    [string]$Gcc = "",
    [string]$JavaHome = "",
    [string]$OutDir = "",
    [string]$SinkDir = "",
    [string]$VmpSdkDir = "",
    [string]$PinnedAuthPubkeyHex = "",
    [string]$ManifestKeyHex = "",
    [string]$PinnedAuthServer = "",
    # #19: Base64 X.509/SPKI of the watermark RSA public key (from the licence server's
    # data/keys/wm-rsa.pub). Without it the client cannot build a watermark payload and the
    # agent silently injects nothing.
    [string]$WmPubKeyB64 = "",
    [ValidateSet("dev", "release")]
    [string]$Configuration = "release"
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$project = Join-Path $root 'chimera-obfuscator'

function Fail([string]$message) {
    Write-Error $message
    exit 1
}

# --- locate OpenSSL static build -------------------------------------------------------------
$candidates = @()
if ($OpenSslDir) { $candidates += $OpenSslDir }
$candidates += (Join-Path $root 'tools\msys2-mingw64\mingw64')
$candidates += (Join-Path $root 'tools\openssl-static\pkg\mingw64')
foreach ($candidate in $candidates) {
    if ((Test-Path (Join-Path $candidate 'include\openssl\evp.h')) -and
        (Test-Path (Join-Path $candidate 'lib\libcrypto.a'))) {
        $OpenSslDir = $candidate
        break
    }
}
if (-not $OpenSslDir -or -not (Test-Path (Join-Path $OpenSslDir 'lib\libcrypto.a'))) {
    Fail ("OpenSSL static libraries not found (need include/openssl + lib/libcrypto.a + lib/libssl.a). " +
          "Download the MSYS2 package once: https://repo.msys2.org/mingw/mingw64/ " +
          "(mingw-w64-x86_64-openssl-<version>-any.pkg.tar.zst) and extract it, or pass -OpenSslDir.")
}
Write-Host "[chimera-native] OpenSSL static dir: $OpenSslDir"

# --- locate compiler -------------------------------------------------------------------------
if (-not $Gcc) {
    $fromToolchain = Join-Path $OpenSslDir 'bin\g++.exe'
    if (Test-Path $fromToolchain) {
        $Gcc = $fromToolchain
    } else {
        $command = Get-Command g++.exe -ErrorAction SilentlyContinue
        if ($command) { $Gcc = $command.Source }
    }
}
if (-not $Gcc -or -not (Test-Path $Gcc)) {
    Fail "g++.exe not found; install MinGW-w64 (same ABI as the OpenSSL static libs) or pass -Gcc."
}
# The static OpenSSL archive is built with the MSYS2 MinGW runtime; use that runtime on PATH.
$binDir = Split-Path -Parent $Gcc
$env:PATH = "$binDir;$env:PATH"
Write-Host "[chimera-native] compiler: $Gcc"

# --- locate JNI headers ----------------------------------------------------------------------
if (-not $JavaHome) { $JavaHome = $env:JAVA_HOME }
if (-not $JavaHome) { $JavaHome = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory() }
$jniInclude = Join-Path $JavaHome 'include'
if (-not (Test-Path (Join-Path $jniInclude 'jni.h'))) {
    Fail "JNI headers not found under $JavaHome (expected include/jni.h); pass -JavaHome."
}

# --- build -----------------------------------------------------------------------------------
$isDevBuild = $Configuration -eq 'dev'
if (-not $OutDir) {
    $OutDir = if ($isDevBuild) { Join-Path $project 'build\native-auth-dev' }
              else { Join-Path $project 'build\native-auth' }
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$output = Join-Path $OutDir 'chimera_auth.dll'
$source = Join-Path $project 'src\main\native\chimera_auth.cpp'
$defines = @()
if ($isDevBuild) { $defines += '-DCHIMERA_DEV_BUILD' }
# SECURITY: bake the licence-server Ed25519 public key into the DLL. Without this, the key comes
# from chimera/auth.dat (an editable jar resource with no integrity coverage), so an attacker
# rewrites server+pubkey to point at their own fake server and forges every response.
if ($PinnedAuthPubkeyHex -ne '') {
    if ($PinnedAuthPubkeyHex -notmatch '^[0-9a-fA-F]{64}$') {
        Fail "PinnedAuthPubkeyHex must be 64 hex characters (32 bytes)"
    }
    # Escaped quotes: PowerShell strips bare quotes when handing args to a native exe, which made
    # g++ see -DCHIMERA_PINNED_AUTH_PUBKEY_HEX=d5d2... and treat the hex as an identifier.
    $defines += ('-DCHIMERA_PINNED_AUTH_PUBKEY_HEX=\"' + $PinnedAuthPubkeyHex + '\"')
    # Second, independent copy of the trust anchor: the SHA-256 of those same 32 bytes, computed
    # here (never passed in) so the two constants can never disagree in a legitimate build. At
    # startup the DLL re-hashes the pinned key and compares; patching the hex string in .rdata to
    # point at an attacker key now fails unless the attacker also recomputes and patches this
    # fingerprint - which is exactly the kind of data-section surgery that VMP makes expensive.
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fpBytes = $sha.ComputeHash([byte[]]::new(0) + ($PinnedAuthPubkeyHex -split '(..)' |
        Where-Object { $_ -ne '' } | ForEach-Object { [Convert]::ToByte($_, 16) }))
    $fpHex = ($fpBytes | ForEach-Object { $_.ToString('x2') }) -join ''
    $defines += ('-DCHIMERA_PINNED_AUTH_PUBKEY_FP_HEX=\"' + $fpHex + '\"')
}
# P2-1: bake the licence-server URL so auth.dat's server= line can no longer repoint the client.
# Empty means "keep reading auth.dat" (dev builds).
if ($PinnedAuthServer -ne '') {
    if ($PinnedAuthServer -notmatch '^https?://[A-Za-z0-9._:\-/]+$') {
        Fail "PinnedAuthServer must look like http(s)://host[:port][/path]"
    }
    $defines += ('-DCHIMERA_PINNED_AUTH_SERVER=\"' + $PinnedAuthServer + '\"')
}
# #9: bake the manifest HMAC key into the DLL. chimera/manifest.dat covers every chimera/**
# resource (auth.dat, env.dat, strings.dat, attach/agent.jar, res/native.dat, wm/*); the jar can
# only carry the tag, so verifying it requires this image. The same value must be passed to the
# engine (--manifest-key) when the jar is built, otherwise the runtime logs that resource
# authentication is unenforced instead of pretending the resources are covered.
if ($ManifestKeyHex -ne '') {
    if ($ManifestKeyHex -notmatch '^[0-9a-fA-F]{64}$') {
        Fail "ManifestKeyHex must be 64 hex characters (32 bytes)"
    }
    # Escaped quotes for the same reason as the pinned auth pubkey above.
    $defines += ('-DCHIMERA_MANIFEST_KEY_HEX=\"' + $ManifestKeyHex + '\"')
    Write-Host "[chimera-native] manifest HMAC key pinned (chimera/manifest.hmac verification ON)"
} else {
    Write-Host "[chimera-native] no manifest HMAC key: the runtime will not authenticate chimera/** resources"
}
$extraIncludes = @()
$extraLibs = @()
if ($WmPubKeyB64 -ne '') {
    if ($WmPubKeyB64 -notmatch '^[A-Za-z0-9+/=]{200,}$') {
        Fail "WmPubKeyB64 must be the Base64 X.509/SPKI of an RSA public key"
    }
    # Escaped quotes for the same reason as the pinned auth pubkey above.
    $defines += ('-DCHIMERA_WM_PUBKEY_B64=\"' + $WmPubKeyB64 + '\"')
    Write-Host "[chimera-native] watermark RSA public key pinned (#19 payload sealing ON)"
} else {
    Write-Host "[chimera-native] no watermark key: the client will not inject per-licence watermarks"
}
if ($VmpSdkDir) {
    $vmpInclude = Join-Path $VmpSdkDir 'Include\C'
    if (-not (Test-Path (Join-Path $vmpInclude 'VMProtectSDK.h'))) { Fail "VMProtectSDK.h not found under $VmpSdkDir" }
    # Link the MSVC import library directly. The SDK's Lib\Windows\MinGW\VMProtectSDK64.a is a
    # pe-i386 archive (measured: objdump -f says "file format pe-i386"), so a 64-bit MinGW link
    # against it fails with undefined __imp_VMProtectBeginVirtualization. GNU ld reads the COFF
    # import library in Lib\Windows just fine and finds the x86-64 __imp_ symbols it wants.
    $vmpLibFile = Join-Path $VmpSdkDir 'Lib\Windows\VMProtectSDK64.lib'
    if (-not (Test-Path $vmpLibFile)) { Fail "VMProtectSDK64.lib not found under $VmpSdkDir (need Lib\Windows)" }
    $defines += '-DCHIMERA_VMP_BUILD'
    $extraIncludes = @("-I$vmpInclude")
    # Order matters for GNU ld: the archive is appended after the objects that reference it.
    $extraLibs = @($vmpLibFile)
    Write-Host "[chimera-native] VMProtect SDK: $vmpLibFile (CHIMERA_VMP_BUILD ON)"
}
$extraSources = @()
if ($SinkDir) {
    $sinkCombined = Join-Path $SinkDir 'chimera_sink_combined.cpp'
    if (-not (Test-Path $sinkCombined)) {
        Fail "SinkDir requires chimera_sink_combined.cpp"
    }
    $defines += '-DCHIMERA_SINK_EXTERNAL_JNI_ONLOAD'
    $extraSources = @($sinkCombined)
}
Write-Host "[chimera-native] configuration: $Configuration$(if ($isDevBuild) { ' (QA hooks ON, never ship this DLL)' })"

$arguments = @(
    '-shared', '-O2', '-std=c++17',
    # Keep float/double arithmetic bit-identical to the Java reference (M4 diff tests).
    '-ffp-contract=off') + $defines + @(
    "-I$(Join-Path $JavaHome 'include')",
    "-I$(Join-Path $JavaHome 'include\win32')",
    "-I$(Join-Path $OpenSslDir 'include')") + $extraIncludes + @(
    '-o', $output, $source) + $extraSources + @(
    "-L$(Join-Path $OpenSslDir 'lib')",
    # Static OpenSSL + static MinGW runtime: the shipped DLL has no third-party dependencies.
    '-static', '-static-libgcc', '-static-libstdc++',
    '-lcrypto', '-lssl') + $extraLibs + @(
    '-lpsapi', '-lws2_32', '-lcrypt32', '-luser32', '-ladvapi32', '-lbcrypt', '-luserenv', '-lwininet'
)
Write-Host "[chimera-native] $Gcc $($arguments -join ' ')"
& $Gcc @arguments
if ($LASTEXITCODE -ne 0) { Fail "native compilation failed (exit $LASTEXITCODE)" }

# --- verify the result is really self-contained ---------------------------------------------
$objdump = Join-Path $binDir 'objdump.exe'
if (Test-Path $objdump) {
    $imports = & $objdump -p $output | Select-String -Pattern 'DLL Name:' |
        ForEach-Object { $_.Line.Trim() }
    Write-Host "[chimera-native] imports:" ($imports -join ', ')
    $forbidden = $imports | Where-Object { $_ -match 'libcrypto|libssl|libgcc|libstdc\+\+|libwinpthread' }
    if ($forbidden) { Fail ("static link check failed; DLL still imports: " + ($forbidden -join ', ')) }
    # Proof that the VMProtect markers actually reached the linker: the SDK import is the only
    # trace they leave before protection, and VMProtect strips it while protecting. A VMP build
    # without this import means the markers were compiled out and the protection step is a no-op.
    if ($VmpSdkDir) {
        if (-not ($imports | Where-Object { $_ -match 'VMProtectSDK64' })) {
            Fail "VMP build does not import VMProtectSDK64.dll: the markers never reached the linker"
        }
        Write-Host "[chimera-native] VMP marker check: VMProtectSDK64.dll imported (markers linked, expected)"
    }

    # Release build must not export the QA-only expiry hook; dev builds must (tests rely on it).
    $exportDump = & $objdump -p $output | Out-String
    $hasExpireHook = $exportDump -match 'nativeExpireHandleForTest'
    if ($isDevBuild) {
        if (-not $hasExpireHook) { Fail "dev DLL must export nativeExpireHandleForTest (tests need the QA hook)" }
        Write-Host "[chimera-native] dev export check: nativeExpireHandleForTest present (expected)"
    } else {
        if ($hasExpireHook) { Fail "release DLL must not export nativeExpireHandleForTest; QA hooks must be compiled out" }
        Write-Host "[chimera-native] release export check: nativeExpireHandleForTest absent (expected)"

        # Phase 0 (C-11): no dev-only bypass marker may survive in the shipped binary.
        $releaseText = [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($output))
        foreach ($marker in @('CHIMERA_TEST_MODE', 'CHIMERA_ALLOW_FRIDA')) {
            if ($releaseText.Contains($marker)) {
                Fail "release DLL must not contain the dev-only marker $marker"
            }
        }
        Write-Host "[chimera-native] release string check: no dev-only bypass markers (expected)"
    }
}

# --- install ---------------------------------------------------------------------------------
if ($isDevBuild) {
    # Dev artifacts stay under build/ and are never shipped.
    Write-Host "[chimera-native] dev DLL at $output ($((Get-Item $output).Length) bytes; QA hooks ON)"
} else {
    $targetDir = Join-Path $project 'native\windows-x64'
    New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
    Copy-Item $output (Join-Path $targetDir 'chimera_auth.dll') -Force
    Remove-Item (Join-Path $targetDir 'libcrypto-3-x64.dll') -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $targetDir 'libssl-3-x64.dll') -Force -ErrorAction SilentlyContinue
    $size = (Get-Item (Join-Path $targetDir 'chimera_auth.dll')).Length
    Write-Host "[chimera-native] installed native/windows-x64/chimera_auth.dll ($size bytes, static OpenSSL, release hooks OFF)"
}
