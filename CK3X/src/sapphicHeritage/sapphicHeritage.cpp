#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace fs = std::filesystem;

struct BytePatch
{
    const wchar_t* name;
    SIZE_T rva;
    SIZE_T length;
    BYTE expected[6];
    BYTE replacement[6];
};

// CK3 1.19.0.6 / 2026-06-04 executable.
static const BytePatch kPatches[] = {
    { L"set_father outer sex guard", 0x2ED8AD2, 2, { 0x74, 0x5A }, { 0xEB, 0x5A } },
    { L"set_father father-ID write guard", 0x2607ACE, 6,
        { 0x0F, 0x85, 0x8F, 0x00, 0x00, 0x00 },
        { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } },
    { L"make_pregnant_no_checks father sex guard", 0x2EE4BD6, 6,
        { 0x0F, 0x84, 0x9E, 0x00, 0x00, 0x00 },
        { 0xE9, 0x9F, 0x00, 0x00, 0x00, 0x90 } },
    { L"make_pregnant father sex guard", 0x2EE5152, 6,
        { 0x0F, 0x84, 0xA2, 0x00, 0x00, 0x00 },
        { 0xE9, 0xA3, 0x00, 0x00, 0x00, 0x90 } },
};

static constexpr const wchar_t* kSupportedCk3Sha256 =
    L"2D00FF3101EF70B566F2FCBAE292F09263199C80E9DC8F139B82D7D96F83DB86";

static fs::path GetModulePath(HMODULE module)
{
    std::vector<wchar_t> buffer(MAX_PATH);
    for (;;) {
        const DWORD length = GetModuleFileNameW(module, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0) {
            return {};
        }
        if (length < buffer.size() - 1) {
            return fs::path(std::wstring(buffer.data(), length));
        }
        buffer.resize(buffer.size() * 2);
    }
}

static fs::path GetLogPath(HMODULE module)
{
    (void)module;

    wchar_t temporaryDirectory[MAX_PATH]{};
    const DWORD length = GetTempPathW(MAX_PATH, temporaryDirectory);
    if (length == 0 || length >= MAX_PATH) {
        return {};
    }

    return fs::path(temporaryDirectory) / L"CK3X" / L"logs" / L"sapphicHeritage.log";
}

static void Log(HMODULE module, const wchar_t* message)
{
    const fs::path logPath = GetLogPath(module);
    std::error_code error;
    fs::create_directories(logPath.parent_path(), error);

    FILE* file = nullptr;
    if (_wfopen_s(&file, logPath.c_str(), L"a, ccs=UTF-8") != 0 || file == nullptr) {
        return;
    }

    SYSTEMTIME now{};
    GetLocalTime(&now);
    fwprintf(
        file,
        L"[%04u-%02u-%02u %02u:%02u:%02u.%03u] %s\r\n",
        now.wYear,
        now.wMonth,
        now.wDay,
        now.wHour,
        now.wMinute,
        now.wSecond,
        now.wMilliseconds,
        message);
    fclose(file);
}

static std::wstring Sha256File(const fs::path& path)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectLength = 0;
    DWORD resultLength = 0;

    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0 ||
        BCryptGetProperty(
            algorithm,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&objectLength),
            sizeof(objectLength),
            &resultLength,
            0) != 0) {
        if (algorithm != nullptr) {
            BCryptCloseAlgorithmProvider(algorithm, 0);
        }
        return {};
    }

    std::vector<BYTE> object(objectLength);
    if (BCryptCreateHash(algorithm, &hash, object.data(), objectLength, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return {};
    }

    std::ifstream file(path, std::ios::binary);
    std::vector<char> buffer(1024 * 1024);
    while (file.good()) {
        file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize read = file.gcount();
        if (read > 0 &&
            BCryptHashData(hash, reinterpret_cast<PUCHAR>(buffer.data()), static_cast<ULONG>(read), 0) != 0) {
            BCryptDestroyHash(hash);
            BCryptCloseAlgorithmProvider(algorithm, 0);
            return {};
        }
    }

    std::vector<BYTE> digest(32);
    const bool finalized = BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) == 0;
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (!finalized) {
        return {};
    }

    std::wostringstream text;
    text << std::uppercase << std::hex << std::setfill(L'0');
    for (const BYTE byte : digest) {
        text << std::setw(2) << static_cast<unsigned>(byte);
    }
    return text.str();
}

static bool ApplyPatch(HMODULE module, HMODULE gameModule, const BytePatch& patch)
{
    BYTE* address = reinterpret_cast<BYTE*>(gameModule) + patch.rva;

    if (std::memcmp(address, patch.replacement, patch.length) == 0) {
        wchar_t message[256]{};
        swprintf_s(message, L"sapphicHeritage: %s already applied at %p", patch.name, address);
        Log(module, message);
        return true;
    }

    if (std::memcmp(address, patch.expected, patch.length) != 0) {
        wchar_t message[256]{};
        swprintf_s(
            message,
            L"sapphicHeritage: REFUSED %s at %p; original bytes do not match this CK3 profile",
            patch.name,
            address);
        Log(module, message);
        return false;
    }

    DWORD oldProtection = 0;
    if (!VirtualProtect(address, patch.length, PAGE_EXECUTE_READWRITE, &oldProtection)) {
        wchar_t message[256]{};
        swprintf_s(message, L"sapphicHeritage: VirtualProtect failed for %s (error %lu)", patch.name, GetLastError());
        Log(module, message);
        return false;
    }

    std::memcpy(address, patch.replacement, patch.length);
    FlushInstructionCache(GetCurrentProcess(), address, patch.length);

    DWORD ignoredProtection = 0;
    VirtualProtect(address, patch.length, oldProtection, &ignoredProtection);

    wchar_t message[256]{};
    swprintf_s(message, L"sapphicHeritage: applied %s at %p", patch.name, address);
    Log(module, message);
    return true;
}

static DWORD WINAPI PluginThread(LPVOID parameter)
{
    const HMODULE module = static_cast<HMODULE>(parameter);
    const HMODULE gameModule = GetModuleHandleW(nullptr);
    if (gameModule == nullptr) {
        Log(module, L"sapphicHeritage: REFUSED because the CK3 main module is unavailable.");
        return 0;
    }

    const fs::path gameExe = GetModulePath(gameModule);
    const std::wstring hash = Sha256File(gameExe);
    if (hash != kSupportedCk3Sha256) {
        wchar_t message[512]{};
        swprintf_s(
            message,
            L"sapphicHeritage: REFUSED unsupported CK3 executable hash %s",
            hash.empty() ? L"<unavailable>" : hash.c_str());
        Log(module, message);
        return 0;
    }

    Log(module, L"sapphicHeritage: CK3 1.19.0.6 profile selected.");
    bool applied = true;
    for (const BytePatch& patch : kPatches) {
        applied = ApplyPatch(module, gameModule, patch) && applied;
    }

    Log(
        module,
        applied
            ? L"sapphicHeritage: all current profile patches are active."
            : L"sapphicHeritage: one or more patches were refused; no test should be trusted.");
    return 0;
}

extern "C" __declspec(dllexport) const wchar_t* CK3X_PluginId()
{
    return L"sapphicHeritage";
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        HANDLE thread = CreateThread(nullptr, 0, PluginThread, module, 0, nullptr);
        if (thread != nullptr) {
            CloseHandle(thread);
        }
    }

    return TRUE;
}
