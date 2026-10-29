#include "manual_map.hpp"
#include "process.hpp"
#include <cstdio>
#include <string>

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) { std::printf("usage: lunar_inject_cli <chemin.dll> [--wipe]\n"); return 1; }

    const auto pid = lunar::injector::find_pid(L"RobloxPlayerBeta.exe");
    if (!pid) { std::printf("RobloxPlayerBeta.exe introuvable\n"); return 1; }

    auto process = lunar::injector::open_process(pid);
    if (!process) { std::printf("ouverture du processus %u refusee\n", pid); return 1; }

    const bool wipe = argc > 2 && std::wstring(argv[2]) == L"--wipe";
    const auto result = lunar::injector::manual_map(process, argv[1], wipe);

    if (!result) { std::printf("echec: %s\n", result.error.c_str()); return 1; }

    std::printf("mappe a 0x%llX\n", static_cast<unsigned long long>(result.base));
    return 0;
}
