#pragma once
#include <windows.h>
#include <cstdint>

namespace lunar::injector {

struct Hijack {
    HANDLE proc = nullptr;
    HANDLE thread = nullptr;
    std::uintptr_t stub = 0;
    std::uintptr_t flag = 0;
    bool done = false;

    ~Hijack();
    Hijack() = default;
    Hijack(const Hijack&) = delete;
    Hijack& operator=(const Hijack&) = delete;
    explicit operator bool() const { return thread != nullptr; }
};

Hijack hijack_thread(HANDLE proc, std::uintptr_t module_base, std::uintptr_t entry);

}
