#include "remote.hpp"
#include "ntdll.hpp"

namespace lunar::injector {

bool read_mem(HANDLE proc, std::uintptr_t addr, void* buf, std::size_t size) {
    std::size_t done = 0;
    const auto st = nt::api().read_virtual_memory(proc, reinterpret_cast<void*>(addr), buf, size, &done);
    return st >= 0 && done == size;
}

bool write_mem(HANDLE proc, std::uintptr_t addr, const void* buf, std::size_t size) {
    std::size_t done = 0;
    const auto st = nt::api().write_virtual_memory(proc, reinterpret_cast<void*>(addr),
                                                   const_cast<void*>(buf), size, &done);
    return st >= 0 && done == size;
}

std::uintptr_t alloc_mem(HANDLE proc, std::size_t size, DWORD protect) {
    void* base = nullptr;
    std::size_t region = size;
    const auto st = nt::api().allocate_virtual_memory(proc, &base, 0, &region,
                                                      MEM_COMMIT | MEM_RESERVE, protect);
    if (st < 0) return 0;
    return reinterpret_cast<std::uintptr_t>(base);
}

bool protect_mem(HANDLE proc, std::uintptr_t addr, std::size_t size, DWORD protect, DWORD* old) {
    void* target = reinterpret_cast<void*>(addr);
    std::size_t region = size;
    ULONG previous = 0;
    const auto st = nt::api().protect_virtual_memory(proc, &target, &region, protect, &previous);
    if (old) *old = previous;
    return st >= 0;
}

bool free_mem(HANDLE proc, std::uintptr_t addr) {
    if (!addr) return false;
    void* target = reinterpret_cast<void*>(addr);
    std::size_t region = 0;
    return nt::api().free_virtual_memory(proc, &target, &region, MEM_RELEASE) >= 0;
}

}
