#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include <bcrypt.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")

namespace fs = std::filesystem;

static fs::path g_rootDirectory;
static fs::path g_logPath;

static fs::path GetCk3XLogPath(const wchar_t* fileName)
{
    wchar_t temporaryDirectory[MAX_PATH]{};
    const DWORD length = GetTempPathW(MAX_PATH, temporaryDirectory);
    if (length == 0 || length >= MAX_PATH) {
        return {};
    }

    return fs::path(temporaryDirectory) / L"CK3X" / L"logs" / fileName;
}

static std::wstring ToLower(std::wstring value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t character) {
        return static_cast<wchar_t>(towlower(character));
    });
    return value;
}

static fs::path GetExecutablePath()
{
    std::vector<wchar_t> buffer(MAX_PATH);
    for (;;) {
        const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0) {
            return {};
        }

        if (length < buffer.size() - 1) {
            return fs::path(std::wstring(buffer.data(), length));
        }

        buffer.resize(buffer.size() * 2);
    }
}

static std::wstring Timestamp()
{
    SYSTEMTIME time{};
    GetLocalTime(&time);

    wchar_t buffer[64]{};
    swprintf_s(
        buffer,
        L"%04u-%02u-%02u %02u:%02u:%02u.%03u",
        time.wYear,
        time.wMonth,
        time.wDay,
        time.wHour,
        time.wMinute,
        time.wSecond,
        time.wMilliseconds);
    return buffer;
}

static void Log(const std::wstring& message)
{
    CreateDirectoryW(g_logPath.parent_path().parent_path().c_str(), nullptr);
    CreateDirectoryW(g_logPath.parent_path().c_str(), nullptr);
    const std::wstring line = L"[" + Timestamp() + L"] " + message + L"\r\n";
    const int byteCount = WideCharToMultiByte(
        CP_UTF8,
        0,
        line.c_str(),
        static_cast<int>(line.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    if (byteCount <= 0) {
        return;
    }

    std::vector<char> utf8(static_cast<size_t>(byteCount));
    if (WideCharToMultiByte(
            CP_UTF8,
            0,
            line.c_str(),
            static_cast<int>(line.size()),
            utf8.data(),
            byteCount,
            nullptr,
            nullptr) <= 0) {
        return;
    }

    HANDLE file = CreateFileW(
        g_logPath.c_str(),
        FILE_APPEND_DATA,
        FILE_SHARE_READ,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(file, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
        CloseHandle(file);
    }
}

static std::wstring LastErrorMessage(DWORD error)
{
    wchar_t* allocated = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        0,
        reinterpret_cast<wchar_t*>(&allocated),
        0,
        nullptr);

    std::wstring message = length == 0 ? L"Unknown Windows error" : std::wstring(allocated, length);
    if (allocated != nullptr) {
        LocalFree(allocated);
    }

    while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n')) {
        message.pop_back();
    }
    return message;
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

static std::vector<fs::path> DiscoverPlugins(const fs::path& modsDirectory)
{
    std::vector<fs::path> plugins;
    std::error_code error;
    if (!fs::exists(modsDirectory, error)) {
        Log(L"CK3X: plugin directory does not exist yet: " + modsDirectory.wstring());
        return plugins;
    }

    for (const fs::directory_entry& entry : fs::directory_iterator(modsDirectory, error)) {
        if (error) {
            const std::string nativeMessage = error.message();
            Log(L"CK3X: could not enumerate plugins: " + std::wstring(nativeMessage.begin(), nativeMessage.end()));
            break;
        }

        if (!entry.is_directory(error)) {
            continue;
        }

        const fs::path candidate = entry.path() / (entry.path().filename().wstring() + L".dll");
        if (fs::is_regular_file(candidate, error)) {
            plugins.push_back(fs::absolute(candidate));
            Log(L"CK3X: discovered plugin " + candidate.wstring());
        } else {
            Log(L"CK3X: skipped " + entry.path().wstring() + L"; expected " + candidate.filename().wstring());
        }
    }

    std::sort(plugins.begin(), plugins.end());
    return plugins;
}

static fs::path GetProcessImagePath(DWORD processId)
{
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (process == nullptr) {
        return {};
    }

    std::vector<wchar_t> buffer(MAX_PATH);
    for (;;) {
        DWORD size = static_cast<DWORD>(buffer.size());
        if (QueryFullProcessImageNameW(process, 0, buffer.data(), &size)) {
            CloseHandle(process);
            return fs::path(std::wstring(buffer.data(), size));
        }

        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            CloseHandle(process);
            return {};
        }

        buffer.resize(buffer.size() * 2);
    }
}

static DWORD FindExpectedCk3Process(const fs::path& expectedGameExe)
{
    std::error_code error;
    const std::wstring expected = ToLower(fs::weakly_canonical(expectedGameExe, error).wstring());
    if (error) {
        return 0;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W process{};
    process.dwSize = sizeof(process);
    DWORD found = 0;
    if (Process32FirstW(snapshot, &process)) {
        do {
            if (_wcsicmp(process.szExeFile, L"ck3.exe") != 0) {
                continue;
            }

            const fs::path imagePath = GetProcessImagePath(process.th32ProcessID);
            const std::wstring actual = ToLower(fs::weakly_canonical(imagePath, error).wstring());
            if (!error && actual == expected) {
                found = process.th32ProcessID;
                break;
            }
            error.clear();
        } while (Process32NextW(snapshot, &process));
    }

    CloseHandle(snapshot);
    return found;
}

static uintptr_t FindRemoteModuleBase(DWORD processId, const wchar_t* moduleName)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    MODULEENTRY32W module{};
    module.dwSize = sizeof(module);
    uintptr_t base = 0;
    if (Module32FirstW(snapshot, &module)) {
        do {
            if (_wcsicmp(module.szModule, moduleName) == 0) {
                base = reinterpret_cast<uintptr_t>(module.modBaseAddr);
                break;
            }
        } while (Module32NextW(snapshot, &module));
    }

    CloseHandle(snapshot);
    return base;
}

static bool InjectPlugin(DWORD processId, const fs::path& plugin)
{
    HANDLE process = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE,
        processId);
    if (process == nullptr) {
        Log(L"CK3X: OpenProcess failed for " + plugin.filename().wstring() + L": " + LastErrorMessage(GetLastError()));
        return false;
    }

    const std::wstring pluginPath = fs::absolute(plugin).wstring();
    const SIZE_T bytes = (pluginPath.size() + 1) * sizeof(wchar_t);
    LPVOID remotePath = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remotePath == nullptr) {
        Log(L"CK3X: VirtualAllocEx failed: " + LastErrorMessage(GetLastError()));
        CloseHandle(process);
        return false;
    }

    if (!WriteProcessMemory(process, remotePath, pluginPath.c_str(), bytes, nullptr)) {
        Log(L"CK3X: WriteProcessMemory failed: " + LastErrorMessage(GetLastError()));
        VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
        CloseHandle(process);
        return false;
    }

    const HMODULE localKernel32 = GetModuleHandleW(L"kernel32.dll");
    const FARPROC localLoadLibrary = localKernel32 == nullptr ? nullptr : GetProcAddress(localKernel32, "LoadLibraryW");
    const uintptr_t remoteKernel32 = FindRemoteModuleBase(processId, L"kernel32.dll");
    if (localLoadLibrary == nullptr || remoteKernel32 == 0) {
        Log(L"CK3X: could not resolve remote LoadLibraryW.");
        VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
        CloseHandle(process);
        return false;
    }

    const uintptr_t localOffset = reinterpret_cast<uintptr_t>(localLoadLibrary) - reinterpret_cast<uintptr_t>(localKernel32);
    const auto remoteLoadLibrary = reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteKernel32 + localOffset);
    HANDLE thread = CreateRemoteThread(process, nullptr, 0, remoteLoadLibrary, remotePath, 0, nullptr);
    if (thread == nullptr) {
        Log(L"CK3X: CreateRemoteThread failed: " + LastErrorMessage(GetLastError()));
        VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
        CloseHandle(process);
        return false;
    }

    const DWORD wait = WaitForSingleObject(thread, 30000);
    DWORD result = 0;
    if (wait == WAIT_OBJECT_0) {
        GetExitCodeThread(thread, &result);
    }

    CloseHandle(thread);
    VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
    CloseHandle(process);

    if (wait != WAIT_OBJECT_0 || result == 0) {
        Log(L"CK3X: LoadLibraryW failed or timed out for " + plugin.filename().wstring());
        return false;
    }

    Log(L"CK3X: injected " + plugin.wstring() + L" into CK3 PID " + std::to_wstring(processId));
    return true;
}

static int RunLauncher(int argc, wchar_t** argv)
{
    g_rootDirectory = GetExecutablePath().parent_path();
    g_logPath = GetCk3XLogPath(L"CK3X.log");

    const fs::path gameExe = g_rootDirectory / L"binaries" / L"ck3.exe";
    const fs::path pluginsDirectory = g_rootDirectory / L"CK3X" / L"mods";
    const bool waitOnly = argc == 2 && _wcsicmp(argv[1], L"--wait-only") == 0;

    if (!fs::is_regular_file(gameExe)) {
        Log(L"CK3X: expected CK3 executable was not found: " + gameExe.wstring());
        return 2;
    }

    const std::vector<fs::path> plugins = DiscoverPlugins(pluginsDirectory);
    if (plugins.empty()) {
        Log(L"CK3X: no valid plugins found. Expected .\\CK3X\\mods\\<modName>\\<modName>.dll");
        return 2;
    }

    Log(L"CK3X: configured CK3 executable: " + gameExe.wstring());
    Log(L"CK3X: CK3 SHA-256: " + Sha256File(gameExe));

    if (!waitOnly) {
        const HINSTANCE launchResult = ShellExecuteW(nullptr, L"open", L"steam://rungameid/1158310", nullptr, nullptr, SW_SHOWNORMAL);
        if (reinterpret_cast<INT_PTR>(launchResult) <= 32) {
            Log(L"CK3X: failed to ask Steam to launch CK3 (ShellExecute result " + std::to_wstring(reinterpret_cast<INT_PTR>(launchResult)) + L").");
            return 1;
        }
        Log(L"CK3X: Steam launch requested. Select your playset and press Play in the Paradox Launcher.");
    } else {
        Log(L"CK3X: wait-only mode enabled. Waiting for CK3 started through an existing launcher.");
    }

    constexpr int kTimeoutSeconds = 900;
    for (int elapsed = 0; elapsed < kTimeoutSeconds * 4; ++elapsed) {
        const DWORD processId = FindExpectedCk3Process(gameExe);
        if (processId != 0) {
            Log(L"CK3X: detected the configured CK3 process, PID " + std::to_wstring(processId));

            bool allInjected = true;
            for (const fs::path& plugin : plugins) {
                allInjected = InjectPlugin(processId, plugin) && allInjected;
            }

            Log(allInjected
                ? L"CK3X: all plugins injected. CK3X is exiting."
                : L"CK3X: one or more plugins failed to inject. See this log for details.");
            return allInjected ? 0 : 1;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    Log(L"CK3X: timed out waiting for the configured CK3 process.");
    return 1;
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int)
{
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv == nullptr) {
        return 1;
    }

    const int result = RunLauncher(argc, argv);
    LocalFree(argv);
    return result;
}
