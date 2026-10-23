# End-to-end v4 activation against a running license server.
#
# The account/password defaults below are throwaway fixtures for a fresh local H2 database. The
# admin token has no default on purpose: pass -BuildToken (or set CHIMERA_BUILD_TOKEN) so this
# script cannot be pointed at a real server with a published credential.
param(
    [string]$Server = 'http://127.0.0.1:8080',
    [string]$Account = 'acceptance',
    [string]$Password = 'acceptance-pass',
    [string]$Hwid = 'acceptance-hwid-001',
    [string]$BuildToken = ''
)
$ErrorActionPreference = 'Stop'
if (-not $BuildToken) { $BuildToken = $env:CHIMERA_BUILD_TOKEN }
if (-not $BuildToken) { throw 'Pass -BuildToken or set CHIMERA_BUILD_TOKEN (the server admin token).' }
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$java = 'C:\Program Files\Eclipse Adoptium\jdk-21.0.12.101-hotspot\bin\java.exe'
$jar = Join-Path $root 'chimera-obfuscator\build\libs\chimera-0.1.0-all.jar'
Write-Host '[e2e] registering account (idempotent for fresh H2)'
try {
    Invoke-RestMethod -Method Post -Uri "$Server/api/v1/license/admin/account" -Headers @{'X-Build-Token'=$BuildToken} -ContentType 'application/json' -Body (@{account=$Account;password=$Password} | ConvertTo-Json) | Out-Null
} catch { Write-Host "[e2e] register skipped: $($_.Exception.Message)" }
$pubkey = (Invoke-RestMethod -Uri "$Server/api/v1/license/pubkey")
$pub = if ($pubkey.pubkey) { $pubkey.pubkey } elseif ($pubkey.publicKey) { $pubkey.publicKey } else { $pubkey | ConvertTo-Json -Compress }
Write-Host "[e2e] server pubkey: $pub"
$state = Join-Path $env:TEMP 'chimera-e2e-license.dat'
& $java -cp $jar dev.chimera.cli.ActivationCli $Server $pub $Account $Password $Hwid $state
Write-Host "[e2e] exit=$LASTEXITCODE"
