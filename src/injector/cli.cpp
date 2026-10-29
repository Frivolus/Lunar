#include "manual_map.hpp"
#include "process.hpp"
#include <cstdio>
#include <cstdlib>
#include <string>

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        std::printf("usage: lunar_inject_cli <dll> [--exe nom.exe] [--pid n] [--wipe]\n");
        return 1;
    }

    const std::wstring dll = argv[1];
    std::wstring exe = L"RobloxPlayerBeta.exe";
    std::uint32_t pid = 0;
    bool wipe = false;

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

    std::printf("cible pid %u, dll %ls\n", pid, dll.c_str());
    const auto result = lunar::injector::manual_map(process, dll, wipe);

    if (!result) { std::printf("echec: %s\n", result.error.c_str()); return 1; }

    std::printf("mappe a 0x%llX\n", static_cast<unsigned long long>(result.base));
    return 0;
}
