# Chimera VMP protection step (release DLL only).
# Usage: powershell -ExecutionPolicy Bypass -File scripts/protect-dll-vmp.ps1 [-VmpDir ...] [-OutDir ...]
#
# Verifies, rather than assumes, that virtualization actually happened. Until 2026-10-22 every
# shipped artifact went through this script and came out with zero virtualized functions (the
# CHIMERA_VMP_BUILD macros were undefined, so VMProtect saw no markers and only compressed the
# image). The checks below make that state impossible to ship again:
#   * at least one "VMProtectMarker" must be reported by the packer,
#   * no marker name may survive in plaintext in the output,
#   * the VMProtectSDK64.dll import must be stripped (the DLL has to stay self-contained).
param(
    [string]$VmpDir = 'G:\VMProtect Ultimate',
    [string]$InputDll = '',
    [string]$OutDir = '',
    # Markers expected in the native source. A missing one means a CHIMERA_VMP_BEGIN/END pair was
    # compiled out (or a function was renamed) - fail loudly instead of shipping less protection.
    # Comma-separated string (not [string[]]) so it can be passed through `powershell -File`.
    [string]$ExpectedMarkers = 'chimera.auth.v4.begin,chimera.auth.v4.finish',
    [int]$MinMarkers = 1
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$project = Join-Path $root 'chimera-obfuscator'
if (-not $InputDll) { $InputDll = Join-Path $project 'native\windows-x64\chimera_auth.dll' }
if (-not $OutDir) { $OutDir = Join-Path $project 'native\windows-x64\vmp' }
$con = Join-Path $VmpDir 'VMProtect_Con.exe'
if (-not (Test-Path $con)) { throw "VMProtect_Con.exe not found under $VmpDir" }
if (-not (Test-Path $InputDll)) { throw "input DLL not found: $InputDll" }
New-Item -ItemType Directory -Force $OutDir | Out-Null
$out = Join-Path $OutDir 'chimera_auth.dll'
if (Test-Path $out) { Remove-Item $out -Force }
Write-Host "[chimera-vmp] $con $InputDll $out"
$report = & $con $InputDll $out 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) { throw "VMProtect failed (exit $LASTEXITCODE)" }
if (-not (Test-Path $out)) { throw "VMProtect reported success but produced no output: $out" }

# --- 1. did the packer see any markers at all? ------------------------------------------------
$markerLines = [regex]::Matches($report, 'VMProtectMarker\s+"([^"]+)"')
$markerNames = @($markerLines | ForEach-Object { $_.Groups[1].Value })
Write-Host ("[chimera-vmp] markers virtualized: " + $markerNames.Count + " (" + ($markerNames -join ', ') + ")")
if ($markerNames.Count -lt $MinMarkers) {
    throw ("VMProtect virtualized 0 functions (expected >= " + $MinMarkers + "). " +
           "The DLL was built without -VmpSdkDir, so CHIMERA_VMP_BUILD was undefined and every " +
           "CHIMERA_VMP_BEGIN/END expanded to nothing. Refusing to ship a compressed-only image.")
}
foreach ($expected in ($ExpectedMarkers -split ',' | Where-Object { $_.Trim() -ne '' } | ForEach-Object { $_.Trim() })) {
    if (-not ($markerNames -contains $expected)) {
        throw ("expected marker '$expected' was not virtualized (found: " + ($markerNames -join ', ') + ")")
    }
}

# --- 2. no marker name may survive in plaintext ------------------------------------------------
$bytes = [System.IO.File]::ReadAllBytes($out)
$ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
$leaked = @($markerNames | Where-Object { $ascii.Contains($_) })
if ($leaked.Count -gt 0) {
    throw ("marker names still readable in the protected image: " + ($leaked -join ', '))
}
Write-Host "[chimera-vmp] marker-name check: no plaintext marker names (expected)"

# --- 3. the SDK import must be gone (self-contained DLL) --------------------------------------
$objdump = Join-Path $root 'tools\msys2-mingw64\mingw64\bin\objdump.exe'
if (Test-Path $objdump) {
    $imports = & $objdump -p $out | Select-String -Pattern 'DLL Name:' | ForEach-Object { $_.Line.Trim() }
    if ($imports | Where-Object { $_ -match 'VMProtectSDK' }) {
        throw "protected DLL still imports VMProtectSDK64.dll; it would fail to load next to the game"
    }
    Write-Host "[chimera-vmp] import check: VMProtectSDK64.dll stripped (expected)"
}

$inSize = (Get-Item $InputDll).Length
$size = (Get-Item $out).Length
Write-Host "[chimera-vmp] protected DLL: $out ($size bytes, was $inSize, VMProtect Ultimate 3.8.4)"
Write-Host '[chimera-vmp] validate with: java -Dchimera.native.auth.path=<out> -cp <app jar> LoadVmpSmoke'
