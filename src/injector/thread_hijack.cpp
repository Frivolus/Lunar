#include "thread_hijack.hpp"
#include "remote.hpp"
#include "ntdll.hpp"
#include <cstdio>
#include <tlhelp32.h>
#include <vector>

namespace lunar::injector {
namespace {

constexpr DWORD kTimeoutMs = 5000;
constexpr DWORD kExitGraceMs = 200;

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

void abort_hijack(Hijack& out, bool suspended) {
    if (out.thread) {
        if (suspended) {
            if (out.stub && out.context) {
                CONTEXT original{};
                original.ContextFlags = CONTEXT_FULL;
                if (read_mem(out.proc, out.context, &original, sizeof(original)))
                    SetThreadContext(out.thread, &original);
            }
            ResumeThread(out.thread);
        }
        CloseHandle(out.thread);
        out.thread = nullptr;
    }
}

bool wait_left_stub(Hijack& out) {
    if (!out.stub || !out.stub_size) return true;

    for (DWORD waited = 0; waited < kExitGraceMs; waited += 2) {
        bool outside = false;
        bool known = false;

        if (SuspendThread(out.thread) != static_cast<DWORD>(-1)) {
            CONTEXT current{};
            current.ContextFlags = CONTEXT_CONTROL;
            known = GetThreadContext(out.thread, &current) != FALSE;
            ResumeThread(out.thread);

            if (known) outside = current.Rip < out.stub || current.Rip >= out.stub + out.stub_size;
        }

        if (outside) return true;
        Sleep(2);
    }
    return false;
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
        abort_hijack(out, false);
        return false;
    }
    bool suspended = true;

    CONTEXT original{};
    original.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(out.thread, &original)) {
        std::fprintf(stderr, "[trace] appel: getcontext echec\n");
        abort_hijack(out, suspended);
        return false;
    }

    const auto nt_continue = nt::api().continue_thread;
    if (!nt_continue) { abort_hijack(out, suspended); return false; }

    out.flag = alloc_mem(proc, 0x10, PAGE_READWRITE);
    out.slot = alloc_mem(proc, 0x10, PAGE_READWRITE);
    if (!out.flag || !out.slot) {
        std::fprintf(stderr, "[trace] appel: alloc echec\n");
        abort_hijack(out, suspended);
        return false;
    }

    out.context = alloc_mem(proc, sizeof(CONTEXT), PAGE_READWRITE);
    if (!out.context || !write_mem(proc, out.context, &original, sizeof(original))) {
        abort_hijack(out, suspended);
        return false;
    }

    auto code = build_stub(fn, a1, a2, a3, out.slot, out.context, out.flag,
                           reinterpret_cast<std::uintptr_t>(nt_continue));

    out.stub = alloc_mem(proc, code.size(), PAGE_EXECUTE_READWRITE);
    if (!out.stub) {
        std::fprintf(stderr, "[trace] appel: stub echec\n");
        abort_hijack(out, suspended);
        return false;
    }
    out.stub_size = code.size();
    if (!write_mem(proc, out.stub, code.data(), code.size())) {
        abort_hijack(out, suspended);
        return false;
    }

    CONTEXT hijacked = original;
    hijacked.Rip = static_cast<DWORD64>(out.stub);
    if (!SetThreadContext(out.thread, &hijacked)) {
        std::fprintf(stderr, "[trace] appel: setcontext echec\n");
        abort_hijack(out, suspended);
        return false;
    }

    ResumeThread(out.thread);
    suspended = false;

    bool done = false;
    for (DWORD waited = 0; waited < kTimeoutMs; waited += 10) {
        std::uint32_t value = 0;
        if (read_value(proc, out.flag, value) && value == 1) { done = true; break; }
        Sleep(10);
    }

    if (!done) {
        std::fprintf(stderr, "[trace] appel: timeout\n");
        out.keep_remote = true;
        if (out_value) read_value(proc, out.slot, *out_value);
        return false;
    }

    if (!wait_left_stub(out)) {
        std::fprintf(stderr, "[trace] appel: sortie du stub non confirmee\n");
        out.keep_remote = true;
    }

    if (out_value) read_value(proc, out.slot, *out_value);
    return true;
}

}

void Hijack::release() {
    if (thread) CloseHandle(thread);
    if (proc && !keep_remote) {
        if (stub) free_mem(proc, stub);
        if (flag) free_mem(proc, flag);
        if (slot) free_mem(proc, slot);
        if (context) free_mem(proc, context);
    }
    thread = nullptr;
    stub = 0;
    stub_size = 0;
    flag = 0;
    slot = 0;
    context = 0;
}

Hijack::Hijack(Hijack&& other) noexcept
    : proc(other.proc), thread(other.thread), stub(other.stub), stub_size(other.stub_size),
      flag(other.flag), slot(other.slot), context(other.context),
      done(other.done), keep_remote(other.keep_remote) {
    other.proc = nullptr;
    other.thread = nullptr;
    other.stub = 0;
    other.stub_size = 0;
    other.flag = 0;
    other.slot = 0;
    other.context = 0;
}

Hijack& Hijack::operator=(Hijack&& other) noexcept {
    if (this != &other) {
        release();
        proc = other.proc;
        thread = other.thread;
        stub = other.stub;
        stub_size = other.stub_size;
        flag = other.flag;
        slot = other.slot;
        context = other.context;
        done = other.done;
        keep_remote = other.keep_remote;
        other.proc = nullptr;
        other.thread = nullptr;
        other.stub = 0;
        other.stub_size = 0;
        other.flag = 0;
        other.slot = 0;
        other.context = 0;
    }
    return *this;
}

Hijack::~Hijack() {
    release();
}

Hijack hijack_thread(HANDLE proc, std::uintptr_t module_base, std::uintptr_t entry) {
    Hijack out;
    out.proc = proc;

    out.thread = pick_thread(GetProcessId(proc));
    if (!out.thread) return out;

    if (SuspendThread(out.thread) == static_cast<DWORD>(-1)) {
        abort_hijack(out, false);
        return out;
    }
    bool suspended = true;

    CONTEXT original{};
    original.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(out.thread, &original)) {
        abort_hijack(out, suspended);
        return out;
    }

    const auto nt_continue = nt::api().continue_thread;
    if (!nt_continue) { abort_hijack(out, suspended); return out; }

    out.flag = alloc_mem(proc, 0x10, PAGE_READWRITE);
    out.slot = alloc_mem(proc, 0x10, PAGE_READWRITE);
    if (!out.flag || !out.slot) { abort_hijack(out, suspended); return out; }

    out.context = alloc_mem(proc, sizeof(CONTEXT), PAGE_READWRITE);
    if (!out.context || !write_mem(proc, out.context, &original, sizeof(original))) {
        abort_hijack(out, suspended);
        return out;
    }

    auto code = build_stub(entry, module_base, 1, 0, out.slot, out.context, out.flag,
                           reinterpret_cast<std::uintptr_t>(nt_continue));

    out.stub = alloc_mem(proc, code.size(), PAGE_EXECUTE_READWRITE);
    if (!out.stub) { abort_hijack(out, suspended); return out; }
    out.stub_size = code.size();
    if (!write_mem(proc, out.stub, code.data(), code.size())) { abort_hijack(out, suspended); return out; }

    CONTEXT hijacked = original;
    hijacked.Rip = static_cast<DWORD64>(out.stub);
    if (!SetThreadContext(out.thread, &hijacked)) { abort_hijack(out, suspended); return out; }

    ResumeThread(out.thread);
    suspended = false;

    for (DWORD waited = 0; waited < kTimeoutMs; waited += 10) {
        std::uint32_t value = 0;
        if (read_value(proc, out.flag, value) && value == 1) { out.done = true; break; }
        Sleep(10);
    }

    if (!out.done) { out.keep_remote = true; return out; }
    if (!wait_left_stub(out)) out.keep_remote = true;

    return out;
}

bool hijack_call(HANDLE proc, std::uintptr_t fn,
                 std::uintptr_t a1, std::uintptr_t a2, std::uintptr_t a3,
                 std::uintptr_t* out_value) {
    return run_stub(proc, fn, a1, a2, a3, out_value);
}

}