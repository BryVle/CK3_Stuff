param(
    [ValidateSet("Debug", "Release")]
    [string] $Configuration = "Release"
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$vswhere = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"

if (-not (Test-Path -LiteralPath $vswhere)) {
    throw "vswhere.exe was not found. Install Visual Studio with the Desktop development with C++ workload."
}

$vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) {
    throw "Visual Studio C++ x64 tools were not found."
}

$vsDevCmd = Join-Path $vsPath "Common7\Tools\VsDevCmd.bat"
$outDir = Join-Path $root "dist"
$pluginDir = Join-Path $outDir "CK3X\mods\sapphicHeritage"

New-Item -ItemType Directory -Path $pluginDir -Force | Out-Null

$optimization = if ($Configuration -eq "Release") { "/O2 /DNDEBUG" } else { "/Od /Zi /D_DEBUG" }
$launcherSource = Join-Path $root "src\CK3X\CK3X.cpp"
$pluginSource = Join-Path $root "src\sapphicHeritage\sapphicHeritage.cpp"
$launcherOut = Join-Path $outDir "CK3X.exe"
$pluginOut = Join-Path $pluginDir "sapphicHeritage.dll"

$command = 'call "{0}" -arch=x64 -host_arch=x64 && cl.exe /nologo /std:c++17 /EHsc /W4 /MD /DUNICODE /D_UNICODE {1} /Fe:"{2}" "{3}" /link bcrypt.lib shell32.lib /SUBSYSTEM:WINDOWS && cl.exe /nologo /std:c++17 /EHsc /W4 /MD /LD /DUNICODE /D_UNICODE {1} /Fe:"{4}" "{5}" /link bcrypt.lib' -f $vsDevCmd, $optimization, $launcherOut, $launcherSource, $pluginOut, $pluginSource

cmd.exe /d /s /c $command
if ($LASTEXITCODE -ne 0) {
    throw "CK3X build failed with exit code $LASTEXITCODE"
}

Write-Host "Build complete:"
Write-Host "  $launcherOut"
Write-Host "  $pluginOut"
