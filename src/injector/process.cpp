#include "process.hpp"
#include "ntdll.hpp"
#include <tlhelp32.h>

namespace lunar::injector {

ProcessHandle::~ProcessHandle() {
    if (handle) CloseHandle(handle);
}

ProcessHandle::ProcessHandle(ProcessHandle&& other) noexcept
    : handle(other.handle), pid(other.pid) {
    other.handle = nullptr;
    other.pid = 0;
}

ProcessHandle& ProcessHandle::operator=(ProcessHandle&& other) noexcept {
    if (this != &other) {
        if (handle) CloseHandle(handle);
        handle = other.handle;
        pid = other.pid;
        other.handle = nullptr;
        other.pid = 0;
    }
    return *this;
}

std::uint32_t find_pid(const wchar_t* exe_name) {
    const HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    std::uint32_t found = 0;

    if (Process32FirstW(snap, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, exe_name) == 0) { found = entry.th32ProcessID; break; }
        } while (Process32NextW(snap, &entry));
    }

    CloseHandle(snap);
    return found;
}

ProcessHandle open_process(std::uint32_t pid) {
    ProcessHandle out;

    const HANDLE raw = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (raw) { out.handle = raw; out.pid = pid; return out; }

    nt::ClientId cid{};
    cid.process = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(pid));

    nt::ObjectAttributes attrs{};
    attrs.length = sizeof(attrs);

    HANDLE native = nullptr;
    if (nt::api().open_process(&native, PROCESS_ALL_ACCESS, &attrs, &cid) >= 0) {
        out.handle = native;
        out.pid = pid;
    }
    return out;
}

std::uintptr_t remote_module_base(HANDLE proc, const wchar_t* module_name) {
    const HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(proc));
    if (snap == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    std::uintptr_t found = 0;

    if (Module32FirstW(snap, &entry)) {
        do {
            if (_wcsicmp(entry.szModule, module_name) == 0) {
                found = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
                break;
            }
        } while (Module32NextW(snap, &entry));
    }

    CloseHandle(snap);
    return found;
}

}

