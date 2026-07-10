param(
    [string] $GameRoot = "F:\SteamMain\steamapps\common\Crusader Kings III"
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$launcher = Join-Path $root "dist\CK3X.exe"
$plugin = Join-Path $root "dist\CK3X\mods\sapphicHeritage\sapphicHeritage.dll"
$gameExe = Join-Path $GameRoot "binaries\ck3.exe"
$targetLauncher = Join-Path $GameRoot "CK3X.exe"
$targetPlugin = Join-Path $GameRoot "CK3X\mods\sapphicHeritage\sapphicHeritage.dll"

if (-not (Test-Path -LiteralPath $launcher)) {
    throw "Build output not found: $launcher"
}

if (-not (Test-Path -LiteralPath $plugin)) {
    throw "Build output not found: $plugin"
}

if (-not (Test-Path -LiteralPath $gameExe)) {
    throw "CK3 executable not found: $gameExe"
}

New-Item -ItemType Directory -Path (Split-Path -Parent $targetPlugin) -Force | Out-Null
Copy-Item -LiteralPath $launcher -Destination $targetLauncher -Force
Copy-Item -LiteralPath $plugin -Destination $targetPlugin -Force

Write-Host "Deployed:"
Write-Host "  $targetLauncher"
Write-Host "  $targetPlugin"
