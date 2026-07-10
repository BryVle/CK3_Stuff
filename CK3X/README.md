# CK3X

CK3X is a native extension launcher for Crusader Kings III.

It leaves Steam, Dowser, the Paradox Launcher, and CK3's mod playlists alone:

1. CK3X asks Steam to launch CK3 normally.
2. The user selects a playset and starts the game in the Paradox Launcher.
3. CK3X waits for the configured CK3 executable.
4. CK3X injects explicitly installed native plugins into that process.

The launcher only scans this layout beside itself:

    CK3X.exe
    CK3X\
      mods\
        <modName>\
          <modName>.dll

The first plugin is sapphicHeritage.dll. It applies only to the supported CK3 executable hash and verifies every original instruction before changing process memory.

## Build

Run:

    powershell.exe -ExecutionPolicy Bypass -File .\build.ps1

## Deploy

Run:

    powershell.exe -ExecutionPolicy Bypass -File .\deploy_to_ck3.ps1

CK3X is installed at the CK3 game root, not in binaries. This keeps the launcher separate from CK3's own executable and bundled runtime DLLs while still resolving binaries\ck3.exe relative to itself.

## Current Scope

sapphicHeritage.dll contains the verified female-father patches and the initial direct-pregnancy patches for CK3 1.19.0.6. It fails closed on any other ck3.exe hash.

Native plugins are intentionally installed outside ordinary CK3 mod folders. CK3X never discovers or executes DLLs embedded in arbitrary local or Workshop mods. Runtime logs are written under the user's temporary directory at TEMP\CK3X\logs.
