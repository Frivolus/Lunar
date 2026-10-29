#pragma once
#include <windows.h>
#include <cstdint>

namespace lunar::injector {

struct ProcessHandle {
    HANDLE handle = nullptr;
    std::uint32_t pid = 0;

    ProcessHandle() = default;
    ~ProcessHandle();
    ProcessHandle(const ProcessHandle&) = delete;
    ProcessHandle& operator=(const ProcessHandle&) = delete;
    ProcessHandle(ProcessHandle&& other) noexcept;
    ProcessHandle& operator=(ProcessHandle&& other) noexcept;

    explicit operator bool() const { return handle != nullptr; }
};

std::uint32_t find_pid(const wchar_t* exe_name);
ProcessHandle open_process(std::uint32_t pid);
std::uintptr_t remote_module_base(HANDLE proc, const wchar_t* module_name);

}

