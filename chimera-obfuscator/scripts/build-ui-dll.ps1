# Build chimera_ui.dll (32-bit and 64-bit) with MSVC BuildTools.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$src = Join-Path $root 'native\ui\chimera_ui.c'
$outDir = Join-Path $root '..\dist-ui'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$vc = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build'
if (-not (Test-Path "$vc\vcvars32.bat")) { throw "MSVC BuildTools vcvars not found: $vc" }

function Build-Arch([string]$arch, [string]$outName, [string]$defName) {
    $vcvars = if ($arch -eq 'x86') { "$vc\vcvars32.bat" } else { "$vc\vcvars64.bat" }
    $def = Join-Path $root "native\ui\$defName"
    $out = Join-Path $outDir $outName
    $cmd = "call ""$vcvars"" >nul && cl /nologo /O2 /W3 /LD /utf-8 /D_CRT_SECURE_NO_WARNINGS ""$src"" /link /DEF:""$def"" /OUT:""$out"" /NOLOGO"
    Write-Host "[build-ui] $arch -> $out"
    cmd /c $cmd
    if ($LASTEXITCODE -ne 0) { throw "$arch build failed (exit $LASTEXITCODE)" }
}

Build-Arch 'x86' 'chimera_ui32.dll' 'chimera_ui32.def'
Build-Arch 'x64' 'chimera_ui64.dll' 'chimera_ui64.def'

Get-ChildItem $outDir -Filter 'chimera_ui*.dll' | ForEach-Object {
    Write-Host ("[build-ui] " + $_.Name + " " + $_.Length + " B")
}
