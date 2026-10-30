#include "thread_hijack.hpp"
#include "remote.hpp"
#include "ntdll.hpp"
#include <cstdio>
#include <tlhelp32.h>
#include <vector>

namespace lunar::injector {
namespace {

constexpr DWORD kTimeoutMs = 5000;

void emit(std::vector<std::uint8_t>& code, std::initializer_list<std::uint8_t> bytes) {
    code.insert(code.end(), bytes.begin(), bytes.end());
}

void emit_imm64(std::vector<std::uint8_t>& code, std::uint8_t rex,
                std::uint8_t opcode, std::uint64_t value) {
    emit(code, { rex, opcode });
    const auto* raw = reinterpret_cast<const std::uint8_t*>(&value);
    code.insert(code.end(), raw, raw + sizeof(value));
}

std::vector<std::uint8_t> build_stub(std::uintptr_t fn, std::uintptr_t a1, std::uintptr_t a2,
                                     std::uintptr_t a3, std::uintptr_t slot,
                                     std::uintptr_t context, std::uintptr_t flag,
                                     std::uintptr_t nt_continue) {
    std::vector<std::uint8_t> code;
    code.reserve(128);

    emit(code, { 0x48, 0x83, 0xE4, 0xF0 });
    emit(code, { 0x48, 0x83, 0xEC, 0x20 });
    emit_imm64(code, 0x48, 0xB9, a1);
    emit_imm64(code, 0x48, 0xBA, a2);
    emit_imm64(code, 0x49, 0xB8, a3);
    emit_imm64(code, 0x48, 0xB8, fn);
    emit(code, { 0xFF, 0xD0 });
    emit_imm64(code, 0x48, 0xB9, slot);
    emit(code, { 0x48, 0x89, 0x01 });
    emit_imm64(code, 0x48, 0xB8, flag);
    emit(code, { 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00 });
    emit_imm64(code, 0x48, 0xB9, context);
    emit(code, { 0x31, 0xD2 });
    emit_imm64(code, 0x48, 0xB8, nt_continue);
    emit(code, { 0xFF, 0xD0 });

    return code;
}

HANDLE pick_thread(std::uint32_t pid) {
    const HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return nullptr;

    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    HANDLE chosen = nullptr;

    if (Thread32First(snap, &entry)) {
        do {
            if (entry.th32OwnerProcessID != pid) continue;
            const HANDLE thread = OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                FALSE, entry.th32ThreadID);
            if (thread) { chosen = thread; break; }
        } while (Thread32Next(snap, &entry));
    }

    CloseHandle(snap);
    return chosen;
}

bool run_stub(HANDLE proc, std::uintptr_t fn, std::uintptr_t a1, std::uintptr_t a2,
              std::uintptr_t a3, std::uintptr_t* out_value) {
    if (out_value) *out_value = 0;

    Hijack out;
    out.proc = proc;

    out.thread = pick_thread(GetProcessId(proc));
    if (!out.thread) { std::fprintf(stderr, "[trace] appel: aucun thread\n"); return false; }

    if (SuspendThread(out.thread) == static_cast<DWORD>(-1)) {
        std::fprintf(stderr, "[trace] appel: suspend echec\n");
        CloseHandle(out.thread);
        out.thread = nullptr;
        return false;
    }

    CONTEXT original{};
    original.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(out.thread, &original)) {
        std::fprintf(stderr, "[trace] appel: getcontext echec\n");
        ResumeThread(out.thread);
        return false;
    }

    const auto nt_continue = nt::api().continue_thread;
    if (!nt_continue) return false;

    out.flag = alloc_mem(proc, 0x10, PAGE_READWRITE);
    out.slot = alloc_mem(proc, 0x10, PAGE_READWRITE);
    if (!out.flag || !out.slot) { std::fprintf(stderr, "[trace] appel: alloc echec\n"); return false; }

    const std::uintptr_t context = alloc_mem(proc, sizeof(CONTEXT), PAGE_READWRITE);
    if (!context) return false;
    if (!write_mem(proc, context, &original, sizeof(original))) return false;

    auto code = build_stub(fn, a1, a2, a3, out.slot, context, out.flag,
                           reinterpret_cast<std::uintptr_t>(nt_continue));

    out.stub = alloc_mem(proc, code.size(), PAGE_EXECUTE_READWRITE);
    if (!out.stub) { std::fprintf(stderr, "[trace] appel: stub echec\n"); return false; }
    if (!write_mem(proc, out.stub, code.data(), code.size())) return false;

    CONTEXT hijacked = original;
    hijacked.Rip = static_cast<DWORD64>(out.stub);
    if (!SetThreadContext(out.thread, &hijacked)) {
        std::fprintf(stderr, "[trace] appel: setcontext echec\n");
        ResumeThread(out.thread);
        return false;
    }

    ResumeThread(out.thread);

    bool done = false;
    for (DWORD waited = 0; waited < kTimeoutMs; waited += 10) {
        std::uint32_t value = 0;
        if (read_value(proc, out.flag, value) && value == 1) { done = true; break; }
        Sleep(10);
    }

    if (!done) { std::fprintf(stderr, "[trace] appel: timeout\n"); return false; }

    if (out_value) read_value(proc, out.slot, *out_value);
    return true;
}

}

Hijack::Hijack(Hijack&& other) noexcept
    : proc(other.proc), thread(other.thread), stub(other.stub),
      flag(other.flag), slot(other.slot), done(other.done) {
    other.proc = nullptr;
    other.thread = nullptr;
    other.stub = 0;
    other.flag = 0;
    other.slot = 0;
}

Hijack& Hijack::operator=(Hijack&& other) noexcept {
    if (this != &other) {
        if (proc) {
            if (stub) free_mem(proc, stub);
            if (flag) free_mem(proc, flag);
            if (slot) free_mem(proc, slot);
        }
        if (thread) CloseHandle(thread);
        proc = other.proc;
        thread = other.thread;
        stub = other.stub;
        flag = other.flag;
        slot = other.slot;
        done = other.done;
        other.proc = nullptr;
        other.thread = nullptr;
        other.stub = 0;
        other.flag = 0;
        other.slot = 0;
    }
    return *this;
}

Hijack::~Hijack() {
    if (proc) {
        if (stub) free_mem(proc, stub);
        if (flag) free_mem(proc, flag);
        if (slot) free_mem(proc, slot);
    }
    if (thread) CloseHandle(thread);
}

Hijack hijack_thread(HANDLE proc, std::uintptr_t module_base, std::uintptr_t entry) {
    Hijack out;
    out.proc = proc;

    out.thread = pick_thread(GetProcessId(proc));
    if (!out.thread) return out;

    if (SuspendThread(out.thread) == static_cast<DWORD>(-1)) {
        CloseHandle(out.thread);
        out.thread = nullptr;
        return out;
    }

    CONTEXT original{};
    original.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(out.thread, &original)) return out;

    const auto nt_continue = nt::api().continue_thread;
    if (!nt_continue) return out;

    out.flag = alloc_mem(proc, 0x10, PAGE_READWRITE);
    out.slot = alloc_mem(proc, 0x10, PAGE_READWRITE);
    if (!out.flag || !out.slot) return out;

    const std::uintptr_t context = alloc_mem(proc, sizeof(CONTEXT), PAGE_READWRITE);
    if (!context) return out;
    if (!write_mem(proc, context, &original, sizeof(original))) return out;

    auto code = build_stub(entry, module_base, 1, 0, out.slot, context, out.flag,
                           reinterpret_cast<std::uintptr_t>(nt_continue));

    out.stub = alloc_mem(proc, code.size(), PAGE_EXECUTE_READWRITE);
    if (!out.stub) return out;
    if (!write_mem(proc, out.stub, code.data(), code.size())) return out;

    CONTEXT hijacked = original;
    hijacked.Rip = static_cast<DWORD64>(out.stub);
    if (!SetThreadContext(out.thread, &hijacked)) return out;

    ResumeThread(out.thread);

    for (DWORD waited = 0; waited < kTimeoutMs; waited += 10) {
        std::uint32_t value = 0;
        if (read_value(proc, out.flag, value) && value == 1) { out.done = true; break; }
        Sleep(10);
    }

    return out;
}

bool hijack_call(HANDLE proc, std::uintptr_t fn,
                 std::uintptr_t a1, std::uintptr_t a2, std::uintptr_t a3,
                 std::uintptr_t* out_value) {
    return run_stub(proc, fn, a1, a2, a3, out_value);
}

}
