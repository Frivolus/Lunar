#include "thread_hijack.hpp"
#include "remote.hpp"
#include "ntdll.hpp"
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

std::vector<std::uint8_t> build_stub(std::uintptr_t module_base, std::uintptr_t entry,
                                     std::uintptr_t context, std::uintptr_t flag,
                                     std::uintptr_t nt_continue) {
    std::vector<std::uint8_t> code;
    code.reserve(96);

    emit(code, { 0x48, 0x83, 0xE4, 0xF0 });                    // and rsp, -16
    emit(code, { 0x48, 0x83, 0xEC, 0x20 });                    // sub rsp, 0x20
    emit_imm64(code, 0x48, 0xB9, module_base);                 // mov rcx, module
    emit(code, { 0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00 });  // mov rdx, 1
    emit(code, { 0x45, 0x31, 0xC0 });                          // xor r8d, r8d
    emit_imm64(code, 0x48, 0xB8, entry);                       // mov rax, entry
    emit(code, { 0xFF, 0xD0 });                                // call rax
    emit_imm64(code, 0x48, 0xB8, flag);                        // mov rax, flag
    emit(code, { 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00 });        // mov dword [rax], 1
    emit_imm64(code, 0x48, 0xB9, context);                     // mov rcx, context
    emit(code, { 0x31, 0xD2 });                                // xor edx, edx
    emit_imm64(code, 0x48, 0xB8, nt_continue);                 // mov rax, NtContinue
    emit(code, { 0xFF, 0xD0 });                                // call rax

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

}

Hijack::Hijack(Hijack&& other) noexcept
    : proc(other.proc), thread(other.thread), stub(other.stub),
      flag(other.flag), done(other.done) {
    other.proc = nullptr;
    other.thread = nullptr;
    other.stub = 0;
    other.flag = 0;
}

Hijack& Hijack::operator=(Hijack&& other) noexcept {
    if (this != &other) {
        if (proc) {
            if (stub) free_mem(proc, stub);
            if (flag) free_mem(proc, flag);
        }
        if (thread) CloseHandle(thread);
        proc = other.proc;
        thread = other.thread;
        stub = other.stub;
        flag = other.flag;
        done = other.done;
        other.proc = nullptr;
        other.thread = nullptr;
        other.stub = 0;
        other.flag = 0;
    }
    return *this;
}

Hijack::~Hijack() {
    if (proc) {
        if (stub) free_mem(proc, stub);
        if (flag) free_mem(proc, flag);
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
    if (!out.flag) return out;

    const std::uintptr_t context = alloc_mem(proc, sizeof(CONTEXT), PAGE_READWRITE);
    if (!context) return out;
    if (!write_mem(proc, context, &original, sizeof(original))) return out;

    auto code = build_stub(module_base, entry, context, out.flag,
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

}

