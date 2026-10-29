#pragma once
#include <windows.h>
#include <cstdint>
#include <cstddef>

namespace lunar::injector {

bool read_mem(HANDLE proc, std::uintptr_t addr, void* buf, std::size_t size);
bool write_mem(HANDLE proc, std::uintptr_t addr, const void* buf, std::size_t size);

std::uintptr_t alloc_mem(HANDLE proc, std::size_t size, DWORD protect);
bool protect_mem(HANDLE proc, std::uintptr_t addr, std::size_t size, DWORD protect, DWORD* old);
bool free_mem(HANDLE proc, std::uintptr_t addr);

template <typename T>
bool read_value(HANDLE proc, std::uintptr_t addr, T& out) {
    return read_mem(proc, addr, &out, sizeof(T));
}

template <typename T>
bool write_value(HANDLE proc, std::uintptr_t addr, const T& in) {
    return write_mem(proc, addr, &in, sizeof(T));
}

}
