$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    & .\gradlew.bat --no-daemon -q clean build :samples:demo:jar
    New-Item -ItemType Directory -Force -Path out | Out-Null
    $cli = 'build\libs\chimera-0.1.0-all.jar'
    $in  = 'samples\demo\build\libs\demo.jar'
    $out = 'out\demo-obf.jar'
    & java -jar $cli --input $in --output $out --key-pass demo-key-123 --native-out out\native
    $env:CHIMERA_CONTENT_KEY = 'demo-key-123'
    & java -jar $out
} finally {
    Remove-Item Env:CHIMERA_CONTENT_KEY -ErrorAction SilentlyContinue
    Pop-Location
}
