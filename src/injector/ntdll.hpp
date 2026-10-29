#pragma once
#include <windows.h>
#include <cstdint>

namespace lunar::injector::nt {

using NtStatus = LONG;

struct ClientId {
    HANDLE process;
    HANDLE thread;
};

struct ObjectAttributes {
    ULONG length;
    HANDLE root;
    PVOID name;
    ULONG attributes;
    PVOID security;
    PVOID security_quality;
};

struct ThreadBasicInformation {
    NtStatus exit_status;
    PVOID teb_base;
    ClientId client_id;
    ULONG_PTR affinity;
    LONG priority;
    LONG base_priority;
};

using FnOpenProcess = NtStatus(NTAPI*)(PHANDLE, ACCESS_MASK, ObjectAttributes*, ClientId*);
using FnReadVirtualMemory = NtStatus(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
using FnWriteVirtualMemory = NtStatus(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
using FnAllocateVirtualMemory = NtStatus(NTAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
using FnProtectVirtualMemory = NtStatus(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
using FnFreeVirtualMemory = NtStatus(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG);
using FnQueryInformationThread = NtStatus(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using FnContinue = NtStatus(NTAPI*)(PCONTEXT, BOOLEAN);

struct Api {
    FnOpenProcess open_process;
    FnReadVirtualMemory read_virtual_memory;
    FnWriteVirtualMemory write_virtual_memory;
    FnAllocateVirtualMemory allocate_virtual_memory;
    FnProtectVirtualMemory protect_virtual_memory;
    FnFreeVirtualMemory free_virtual_memory;
    FnQueryInformationThread query_information_thread;
    FnContinue continue_thread;
};

inline Api& api() {
    static Api instance = [] {
        Api a{};
        const auto ntdll = GetModuleHandleW(L"ntdll.dll");
        a.open_process = reinterpret_cast<FnOpenProcess>(GetProcAddress(ntdll, "NtOpenProcess"));
        a.read_virtual_memory = reinterpret_cast<FnReadVirtualMemory>(GetProcAddress(ntdll, "NtReadVirtualMemory"));
        a.write_virtual_memory = reinterpret_cast<FnWriteVirtualMemory>(GetProcAddress(ntdll, "NtWriteVirtualMemory"));
        a.allocate_virtual_memory = reinterpret_cast<FnAllocateVirtualMemory>(GetProcAddress(ntdll, "NtAllocateVirtualMemory"));
        a.protect_virtual_memory = reinterpret_cast<FnProtectVirtualMemory>(GetProcAddress(ntdll, "NtProtectVirtualMemory"));
        a.free_virtual_memory = reinterpret_cast<FnFreeVirtualMemory>(GetProcAddress(ntdll, "NtFreeVirtualMemory"));
        a.query_information_thread = reinterpret_cast<FnQueryInformationThread>(GetProcAddress(ntdll, "NtQueryInformationThread"));
        a.continue_thread = reinterpret_cast<FnContinue>(GetProcAddress(ntdll, "NtContinue"));
        return a;
    }();
    return instance;
}

constexpr ULONG kThreadBasicInformation = 0;

}
