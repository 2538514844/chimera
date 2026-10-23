# Starts the license server for local acceptance tests.
#
# CHIMERA_RESOURCE_KEY_HEX and CHIMERA_BUILD_TOKEN must be supplied. They are NOT defaulted to a
# known value: a published default is a published credential, and the ResourceKey is what decrypts
# the product artifact - anyone holding it can read every class body. If you are just kicking the
# tyres, let this script generate a fresh pair and then build the client with the same ResourceKey.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$env:GRADLE_USER_HOME = Join-Path $root 'tools\gradle-home'

function New-RandomHex([int]$Bytes) {
    $buffer = New-Object byte[] $Bytes
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($buffer)
    return -join ($buffer | ForEach-Object { $_.ToString('x2') })
}

if (-not $env:CHIMERA_RESOURCE_KEY_HEX) {
    $env:CHIMERA_RESOURCE_KEY_HEX = New-RandomHex 32
    Write-Host '[license-server] generated a fresh ResourceKey (build the client with it):'
    Write-Host ('  ' + $env:CHIMERA_RESOURCE_KEY_HEX)
}
if (-not $env:CHIMERA_BUILD_TOKEN) {
    $env:CHIMERA_BUILD_TOKEN = New-RandomHex 24
    Write-Host '[license-server] generated a fresh admin token:'
    Write-Host ('  ' + $env:CHIMERA_BUILD_TOKEN)
}

if ($env:CHIMERA_RESOURCE_KEY_HEX -notmatch '^[0-9a-fA-F]{64}$') {
    throw 'CHIMERA_RESOURCE_KEY_HEX must be 64 hex characters (32 bytes).'
}

Write-Host '[license-server] starting on :8080 (H2 ./data/chimera)'
& (Join-Path $root 'tools\gradle-8.10.2\bin\gradle.bat') --no-daemon -p (Join-Path $root 'chimera-license-server') bootRun
