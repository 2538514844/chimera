param(
    [string]$WurstJar = 'G:\vibecoding\chimare\work\wurst\Wurst-Client-v7.51.2-MC1.21.1.jar',
    [string]$OutDir = 'G:\vibecoding\chimare\dist',
    [string]$KeyPass = 'prism-test-key-2026',
    [switch]$NativeSink,
    [switch]$Vmp,
    [string]$AuthServer = '',
    [string]$AuthPubkey = ''
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$project = Join-Path $root 'chimera-obfuscator'
$env:GRADLE_USER_HOME = Join-Path $root 'tools\gradle-home'
$java = 'C:\Program Files\Eclipse Adoptium\jdk-21.0.12.101-hotspot\bin\java.exe'
$gradlew = Join-Path $project 'gradlew.bat'
function Invoke-Java([string[]]$javaArgs, [string]$logFile) {
    $out = Start-Process -FilePath $java -ArgumentList $javaArgs -NoNewWindow -Wait -PassThru -RedirectStandardOutput $logFile -RedirectStandardError "$logFile.err"
    return $out.ExitCode
}
$work = Join-Path $root 'work\pack'
New-Item -ItemType Directory -Force $work, $OutDir | Out-Null

Write-Host '[package] 1/6 build obfuscator'
& $gradlew --no-daemon -q -p $project shadowJar
if ($LASTEXITCODE -ne 0) { throw 'shadowJar failed' }
$toolJar = Join-Path $project 'build\libs\chimera-0.1.0-all.jar'

$cp = 'G:\vibecoding\chimare\work\phs\libs\mc-intermediary-1.21.1.jar;G:\PCL\.minecraft\versions\1.21.1-Fabric 0.19.3\mods\fabric-api-0.116.15+1.21.1.jar'
$product = Join-Path $work 'Wurst-protected.jar'
$args = @(
    '-jar', $toolJar, '--input', $WurstJar, '--output', $product,
    '--key-pass', $KeyPass,
    '--harden', '--indy', '--invisible-naming', '--short-names', '--strip-debug',
    '--mixin-support', '--strip-refmap', '--field-init-sink', '--invoke-wrapper',
    '--cfg', '--compute-frames', '--watermark', '--wm-license', 'acceptance',
    '--classpath', ('"' + $cp + '"'), '--classpath-dir', 'G:\PCL\.minecraft\libraries',
    '--no-native', '--no-vm', '--no-fragments', '--no-entangle', '--no-honeypot', '--no-rename'
)
if ($NativeSink) { $args += '--native-sink' }
if ($AuthServer -ne '' -and $AuthPubkey -ne '') {
    $args += @('--auth-gate', '--auth-server', $AuthServer, '--auth-pubkey', $AuthPubkey)
}
Write-Host '[package] 2/6 protect mod'
$rc = Invoke-Java $args (Join-Path $work 'build.log')
if ($rc -ne 0) { throw "product build failed (exit $rc); see work/pack/build.log" }

Write-Host '[package] 3/6 build native DLL'
$sinkDir = Join-Path $work 'chimera-sink'
$nativeScript = Join-Path $project 'scripts\build-native-auth.ps1'
if ($NativeSink) {
    & powershell -NoProfile -ExecutionPolicy Bypass -File $nativeScript -Configuration release -SinkDir $sinkDir
} else {
    & powershell -NoProfile -ExecutionPolicy Bypass -File $nativeScript -Configuration release
}
if ($LASTEXITCODE -ne 0) { throw 'native build failed' }
$dll = Join-Path $project 'build\native-auth\chimera_auth.dll'
if (-not (Test-Path $dll)) { throw "DLL missing: $dll" }

if ($Vmp) {
    Write-Host '[package] 4/6 VMProtect DLL'
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $project 'scripts\protect-dll-vmp.ps1') -InputDll $dll -OutDir (Join-Path $work 'vmp')
    if ($LASTEXITCODE -ne 0) { throw 'VMProtect failed' }
    $dll = Join-Path $work 'vmp\chimera_auth.dll'
} else {
    Write-Host '[package] 4/6 skip VMProtect'
}

Write-Host '[package] 5/6 payload overlay'
$overlayArgs = @('-jar', $toolJar, '--input', $WurstJar, '--output', (Join-Path $work 'overlay-probe.jar'), '--key-pass', $KeyPass, '--payload-overlay', $dll, '--no-native', '--no-vm', '--no-fragments', '--no-entangle', '--no-honeypot', '--no-rename', '--no-harden')
$rc = Invoke-Java $overlayArgs (Join-Path $work 'overlay.log')
$packed = Join-Path $work 'chimera_auth.dll.packed'
if (Test-Path $packed) { Copy-Item $packed (Join-Path $OutDir 'chimera_auth.dll.packed') -Force }

Write-Host '[package] 6/6 write dist'
Copy-Item $product (Join-Path $OutDir 'Wurst-protected.jar') -Force
Copy-Item $dll (Join-Path $OutDir 'chimera_auth.dll') -Force
$info = [ordered]@{
    builtAt = (Get-Date).ToString('o')
    input = $WurstJar
    nativeSink = [bool]$NativeSink
    vmp = [bool]$Vmp
    keyPassMode = 'legacy'
}
$info | ConvertTo-Json | Set-Content (Join-Path $OutDir 'build-info.json') -Encoding UTF8
Get-ChildItem $OutDir -File | Get-FileHash -Algorithm SHA256 |
    ForEach-Object { "$($_.Hash.ToLower())  $($_.Path | Split-Path -Leaf)" } |
    Set-Content (Join-Path $OutDir 'SHA256SUMS.txt') -Encoding ASCII
Write-Host "[package] done: $OutDir"
Get-ChildItem $OutDir -File | Select-Object Name,Length
