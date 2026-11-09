#include "manual_map.hpp"
#include "process.hpp"
#include "thread_hijack.hpp"
#include <cstdio>
#include <cstdlib>
#include <string>

int wmain(int argc, wchar_t** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    if (argc < 2) {
        std::printf("usage: lunar_inject_cli <dll|--selftest> [--exe nom.exe] [--pid n] [--wipe]\n");
        return 1;
    }

    std::wstring dll = argv[1];
    std::wstring exe = L"RobloxPlayerBeta.exe";
    std::uint32_t pid = 0;
    bool wipe = false;
    bool selftest = dll == L"--selftest";

    for (int i = 2; i < argc; ++i) {
        const std::wstring arg = argv[i];
        if (arg == L"--wipe") { wipe = true; }
        else if (arg == L"--exe" && i + 1 < argc) { exe = argv[++i]; }
        else if (arg == L"--pid" && i + 1 < argc) { pid = static_cast<std::uint32_t>(_wtoi(argv[++i])); }
    }

    if (!pid) pid = lunar::injector::find_pid(exe.c_str());
    if (!pid) { std::wprintf(L"processus %s introuvable\n", exe.c_str()); return 1; }

    auto process = lunar::injector::open_process(pid);
    if (!process) { std::printf("ouverture du pid %u refusee\n", pid); return 1; }

    std::printf("cible pid %u\n", pid);

    if (selftest) {
        const auto fn = reinterpret_cast<std::uintptr_t>(
            GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetCurrentProcessId"));
        std::uintptr_t remote_pid = 0;
        const bool ok = lunar::injector::hijack_call(process.handle, fn, 0, 0, 0, &remote_pid);
        std::printf("selftest: appel=%d valeur=%llu attendu=%u\n", ok ? 1 : 0,
                    static_cast<unsigned long long>(remote_pid), pid);
        return ok && remote_pid == pid ? 0 : 1;
    }

    const auto result = lunar::injector::manual_map(process, dll, wipe);

    if (!result) {
        std::printf("echec a l'etape [%s] : %s\n", result.stage.c_str(), result.error.c_str());
        return 1;
    }

    std::printf("mappe a 0x%llX\n", static_cast<unsigned long long>(result.base));
    return 0;
}