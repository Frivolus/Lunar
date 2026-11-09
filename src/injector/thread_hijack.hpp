#pragma once
#include <windows.h>
#include <cstdint>
#include <cstddef>

namespace lunar::injector {

struct Hijack {
    HANDLE proc = nullptr;
    HANDLE thread = nullptr;
    std::uintptr_t stub = 0;
    std::size_t stub_size = 0;
    std::uintptr_t flag = 0;
    std::uintptr_t slot = 0;
    std::uintptr_t context = 0;
    bool done = false;
    bool keep_remote = false;

    ~Hijack();
    Hijack() = default;
    Hijack(const Hijack&) = delete;
    Hijack& operator=(const Hijack&) = delete;
    Hijack(Hijack&& other) noexcept;
    Hijack& operator=(Hijack&& other) noexcept;

    void release();

    explicit operator bool() const { return thread != nullptr; }
};

Hijack hijack_thread(HANDLE proc, std::uintptr_t module_base, std::uintptr_t entry);

bool hijack_call(HANDLE proc, std::uintptr_t fn,
                 std::uintptr_t a1, std::uintptr_t a2, std::uintptr_t a3,
                 std::uintptr_t* out_value);

}