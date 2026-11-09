#include "manual_map.hpp"
#include "remote.hpp"
#include "peb.hpp"
#include "thread_hijack.hpp"
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <tlhelp32.h>
#include <fstream>
#include <vector>

namespace lunar::injector {
namespace {

constexpr std::size_t kMaxImage = 256u * 1024u * 1024u;
std::filesystem::path g_dll_dir;

std::vector<std::uint8_t> read_file(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) return {};

    stream.seekg(0, std::ios::end);
    const auto size = static_cast<std::size_t>(stream.tellg());
    if (!size) return {};

    stream.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> buffer(size);
    stream.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(size));
    if (static_cast<std::size_t>(stream.gcount()) != size) return {};
    return buffer;
}

bool build_local_image(const std::vector<std::uint8_t>& file, std::vector<std::uint8_t>& out) {
    if (file.size() < sizeof(IMAGE_DOS_HEADER)) return false;

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(file.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (dos->e_lfanew <= 0) return false;

    const auto header_end = static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64);
    if (header_end > file.size()) return false;

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(file.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return false;

    const auto image_size = static_cast<std::size_t>(nt->OptionalHeader.SizeOfImage);
    if (!image_size || image_size > kMaxImage) return false;
    if (nt->OptionalHeader.SizeOfHeaders > image_size) return false;

    out.assign(image_size, 0);
    std::memcpy(out.data(), file.data(), nt->OptionalHeader.SizeOfHeaders);

    auto* section = IMAGE_FIRST_SECTION(nt);
    for (std::size_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        if (!section->SizeOfRawData) continue;

        const auto dest = static_cast<std::size_t>(section->VirtualAddress);
        const auto src = static_cast<std::size_t>(section->PointerToRawData);

        if (dest + section->SizeOfRawData > image_size) return false;
        if (src + section->SizeOfRawData > file.size()) return false;

        std::memcpy(out.data() + dest, file.data() + src, section->SizeOfRawData);
    }
    return true;
}

const IMAGE_DATA_DIRECTORY* directory(const std::uint8_t* image, std::size_t image_size,
                                      std::size_t index) {
    if (image_size < sizeof(IMAGE_DOS_HEADER)) return nullptr;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
    if (dos->e_lfanew <= 0) return nullptr;

    const auto header_end = static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64);
    if (header_end > image_size) return nullptr;

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image + dos->e_lfanew);
    return &nt->OptionalHeader.DataDirectory[index];
}

const char* remap_apiset(const char* name) {
    if (!name) return nullptr;
    if (std::strncmp(name, "api-ms-win-crt-", 15) == 0) return "ucrtbase.dll";
    if (std::strncmp(name, "api-ms-win-core-", 16) == 0) return "kernelbase.dll";
    if (std::strncmp(name, "api-ms-win-security-", 20) == 0) return "kernelbase.dll";
    if (std::strncmp(name, "api-ms-win-eventing-", 20) == 0) return "kernelbase.dll";
    if (std::strncmp(name, "ext-ms-win-", 11) == 0) return "kernelbase.dll";
    return nullptr;
}

bool apply_relocations(HANDLE proc, std::uintptr_t base, const std::uint8_t* image,
                       std::size_t image_size, std::int64_t delta) {
    const auto* reloc = directory(image, image_size, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (!reloc || !reloc->Size) return true;
    if (static_cast<std::size_t>(reloc->VirtualAddress) >= image_size) return false;

    std::size_t offset = 0;
    std::size_t patched = 0;
    while (offset + sizeof(IMAGE_BASE_RELOCATION) <= reloc->Size) {
        const auto block_offset = static_cast<std::size_t>(reloc->VirtualAddress) + offset;
        if (block_offset + sizeof(IMAGE_BASE_RELOCATION) > image_size) break;

        const auto* block = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(image + block_offset);
        if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;
        if (block_offset + block->SizeOfBlock > image_size) break;

        const auto count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(std::uint16_t);
        const auto* entries = reinterpret_cast<const std::uint16_t*>(block + 1);

        for (std::size_t i = 0; i < count; ++i) {
            const std::uint16_t entry = entries[i];
            if ((entry >> 12) != IMAGE_REL_BASED_DIR64) continue;

            const std::uintptr_t patch = base + block->VirtualAddress + (entry & 0x0FFF);
            std::uint64_t value = 0;
            if (!read_value(proc, patch, value)) return false;
            value = static_cast<std::uint64_t>(static_cast<std::int64_t>(value) + delta);
            if (!write_value(proc, patch, value)) return false;
            ++patched;
        }

        offset += block->SizeOfBlock;
    }
    std::fprintf(stderr, "[trace] relocations appliquees: %zu", patched); std::fprintf(stderr, "\n");
    return true;
}

bool load_remote(HANDLE proc, const wchar_t* name, std::uintptr_t& out_module);

std::uintptr_t resolve_export_depth(HANDLE proc, std::uintptr_t module,
                                    const char* name, std::uint16_t ordinal_hint, int depth) {
    if (!module) return 0;
    if (depth > 8) return 0;

    IMAGE_DOS_HEADER dos{};
    if (!read_value(proc, module, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;

    IMAGE_NT_HEADERS64 nt{};
    if (!read_value(proc, module + dos.e_lfanew, nt) || nt.Signature != IMAGE_NT_SIGNATURE)
        return 0;

    const auto& export_dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!export_dir.VirtualAddress) return 0;

    IMAGE_EXPORT_DIRECTORY dir{};
    if (!read_value(proc, module + export_dir.VirtualAddress, dir)) return 0;
    if (!dir.NumberOfFunctions || !dir.NumberOfNames) return 0;

    // Un export qui pointe dans .edata est un forwarder "DLL.Fonction".
    // Renvoyer son RVA tel quel ferait executer une page non executable.
    auto finish = [&](std::uint32_t rva) -> std::uintptr_t {
        const auto first = static_cast<std::uint32_t>(export_dir.VirtualAddress);
        const auto last = first + static_cast<std::uint32_t>(export_dir.Size);
        if (rva < first || rva >= last) return module + rva;

        char forwarder[256]{};
        if (!read_mem(proc, module + rva, forwarder, sizeof(forwarder) - 1)) return 0;

        char* dot = std::strchr(forwarder, '.');
        if (!dot) return 0;
        *dot = 0;

        wchar_t host_name[128]{};
        MultiByteToWideChar(CP_ACP, 0, forwarder, -1, host_name, 128);

        std::uintptr_t host = remote_module_base(proc, host_name);
        if (!host) {
            std::wstring with_ext = host_name;
            if (with_ext.find(L'.') == std::wstring::npos) with_ext += L".dll";
            std::uintptr_t loaded = 0;
            if (load_remote(proc, with_ext.c_str(), loaded)) host = loaded;
        }
        if (!host) {
            std::fprintf(stderr, "[trace] forwarder non resolu : %s\n", forwarder);
            return 0;
        }

        return resolve_export_depth(proc, host, dot + 1, 0, depth + 1);
    };

    std::vector<std::uint32_t> funcs(dir.NumberOfFunctions);
    if (!read_mem(proc, module + dir.AddressOfFunctions,
                  funcs.data(), funcs.size() * sizeof(std::uint32_t))) return 0;

    if (!name) {
        const auto index = static_cast<std::size_t>(ordinal_hint - dir.Base);
        if (index >= funcs.size()) return 0;
        return finish(funcs[index]);
    }

    std::vector<std::uint32_t> names(dir.NumberOfNames);
    std::vector<std::uint16_t> ordinals(dir.NumberOfNames);
    if (!read_mem(proc, module + dir.AddressOfNames,
                  names.data(), names.size() * sizeof(std::uint32_t))) return 0;
    if (!read_mem(proc, module + dir.AddressOfNameOrdinals,
                  ordinals.data(), ordinals.size() * sizeof(std::uint16_t))) return 0;

    for (std::size_t i = 0; i < names.size(); ++i) {
        char buffer[256]{};
        if (!read_mem(proc, module + names[i], buffer, sizeof(buffer) - 1)) continue;
        if (std::strcmp(buffer, name) != 0) continue;
        if (ordinals[i] >= funcs.size()) return 0;
        return finish(funcs[ordinals[i]]);
    }
    return 0;
}

std::uintptr_t resolve_export(HANDLE proc, std::uintptr_t module,
                              const char* name, std::uint16_t ordinal_hint) {
    return resolve_export_depth(proc, module, name, ordinal_hint, 0);
}

bool load_remote(HANDLE proc, const wchar_t* name, std::uintptr_t& out_module) {
    const auto load_library = reinterpret_cast<std::uintptr_t>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"));
    if (!load_library) return false;

    const auto byte_size = (std::wcslen(name) + 1) * sizeof(wchar_t);
    const auto remote_name = alloc_mem(proc, byte_size, PAGE_READWRITE);
    if (!remote_name) return false;
    if (!write_mem(proc, remote_name, name, byte_size)) return false;

    std::uintptr_t loaded = 0;
    const bool ok = hijack_call(proc, load_library, remote_name, 0, 0, &loaded);
    free_mem(proc, remote_name);

    out_module = ok ? loaded : 0;
    return ok && loaded;
}

// Le CRT appelle RtlPcToFileHeader pour retrouver l'ImageBase. Sans entree dans
// l'InvertedFunctionTable il renvoie 0 et le CRT plante. On detourne l'import.
bool patch_pc_to_file_header(HANDLE proc, std::uintptr_t base, const std::uint8_t* image,
                             std::size_t image_size) {
    const auto real = reinterpret_cast<std::uintptr_t>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "RtlPcToFileHeader"));
    if (!real) { std::fprintf(stderr, "[trace] RtlPcToFileHeader introuvable\n"); return true; }

    const auto* imports = directory(image, image_size, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (!imports || !imports->Size) return true;

    std::vector<std::uint8_t> stub;
    auto push_imm64 = [&](std::uint8_t rex, std::uint8_t op, std::uintptr_t value) {
        stub.push_back(rex); stub.push_back(op);
        const auto* p = reinterpret_cast<const std::uint8_t*>(&value);
        stub.insert(stub.end(), p, p + sizeof(value));
    };

    stub.push_back(0x49); stub.push_back(0x89); stub.push_back(0xC9);          // mov r9, rcx
    push_imm64(0x49, 0xB8, base);                                             // mov r8, base
    stub.push_back(0x4C); stub.push_back(0x29); stub.push_back(0xC9);          // sub r9, r8
    stub.push_back(0x49); stub.push_back(0x81); stub.push_back(0xF9);          // cmp r9, size
    const auto size32 = static_cast<std::uint32_t>(image_size);
    const auto* s = reinterpret_cast<const std::uint8_t*>(&size32);
    stub.insert(stub.end(), s, s + sizeof(size32));
    stub.push_back(0x73); stub.push_back(0x07);                               // jae fin
    stub.push_back(0x4C); stub.push_back(0x89); stub.push_back(0x02);          // mov [rdx], r8
    stub.push_back(0x4C); stub.push_back(0x89); stub.push_back(0xC0);          // mov rax, r8
    stub.push_back(0xC3);                                                     // ret
    push_imm64(0x49, 0xB8, real);                                             // mov r8, real
    stub.push_back(0x41); stub.push_back(0xFF); stub.push_back(0xE0);          // jmp r8

    const auto remote = alloc_mem(proc, stub.size(), PAGE_EXECUTE_READWRITE);
    if (!remote) return false;
    if (!write_mem(proc, remote, stub.data(), stub.size())) return false;

    std::size_t patched = 0;
    const auto* descriptor = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
        image + imports->VirtualAddress);

    for (; descriptor->Name; ++descriptor) {
        const auto* thunk = reinterpret_cast<const IMAGE_THUNK_DATA64*>(image + descriptor->FirstThunk);
        std::uintptr_t slot = base + descriptor->FirstThunk;

        for (; thunk->u1.AddressOfData; ++thunk, slot += sizeof(std::uint64_t)) {
            if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) continue;
            const auto* by_name = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
                image + thunk->u1.AddressOfData);
            if (std::strcmp(reinterpret_cast<const char*>(by_name->Name), "RtlPcToFileHeader") != 0)
                continue;

            if (!write_value(proc, slot, remote)) return false;
            ++patched;
        }
    }

    std::fprintf(stderr, "[trace] RtlPcToFileHeader detourne (%zu emplacement)\n", patched);
    return true;
}
using FnHandleTls = LONG(NTAPI*)(PVOID);
using FnAddFunctionTable = BOOLEAN(NTAPI*)(PRUNTIME_FUNCTION, DWORD, DWORD64);

// Enregistre la table d'exceptions .pdata : sans elle, le moindre unwind tue le thread.
bool register_exceptions(HANDLE proc, std::uintptr_t base, const std::uint8_t* image,
                         std::size_t image_size) {
    const auto* dir = directory(image, image_size, IMAGE_DIRECTORY_ENTRY_EXCEPTION);
    if (!dir || !dir->Size) { std::fprintf(stderr, "[trace] pas de .pdata\n"); return true; }
    if (static_cast<std::size_t>(dir->VirtualAddress) + dir->Size > image_size) return false;

    const auto add_table = reinterpret_cast<FnAddFunctionTable>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlAddFunctionTable"));
    if (!add_table) return false;

    const auto remote = alloc_mem(proc, dir->Size, PAGE_READWRITE);
    if (!remote) return false;
    if (!write_mem(proc, remote, image + dir->VirtualAddress, dir->Size)) return false;

    const DWORD count = dir->Size / sizeof(RUNTIME_FUNCTION);
    std::uintptr_t ignored = 0;
    const bool ok = hijack_call(proc, reinterpret_cast<std::uintptr_t>(add_table),
                                remote, count, base, &ignored);
    std::fprintf(stderr, "[trace] table d'exceptions: %lu entrees, appel distant=%d\n", count, ok ? 1 : 0);
    return ok;
}

// Alloue les slots TLS puis appelle les callbacks TLS du module.
bool run_tls(HANDLE proc, std::uintptr_t base, std::uintptr_t preferred,
             const std::uint8_t* image, std::size_t image_size) {
    const auto* dir = directory(image, image_size, IMAGE_DIRECTORY_ENTRY_TLS);
    if (!dir || !dir->Size) { std::fprintf(stderr, "[trace] pas de TLS\n"); return true; }
    if (static_cast<std::size_t>(dir->VirtualAddress) + sizeof(IMAGE_TLS_DIRECTORY64) > image_size)
        return false;

    IMAGE_TLS_DIRECTORY64 tls{};
    std::memcpy(&tls, image + dir->VirtualAddress, sizeof(tls));

    const auto handle_tls = reinterpret_cast<FnHandleTls>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrpHandleTlsData"));
    if (handle_tls) {
        std::uintptr_t ignored = 0;
        const bool ok = hijack_call(proc, reinterpret_cast<std::uintptr_t>(handle_tls),
                                    base, 0, 0, &ignored);
        std::fprintf(stderr, "[trace] LdrpHandleTlsData -> %d\n", ok ? 1 : 0);
    }

    if (!tls.AddressOfCallBacks) return true;

    const auto list_rva = static_cast<std::size_t>(tls.AddressOfCallBacks - preferred);
    if (list_rva + sizeof(std::uint64_t) > image_size) return false;

    for (std::size_t i = 0; i < 64; ++i) {
        std::uint64_t callback = 0;
        const auto slot = list_rva + i * sizeof(std::uint64_t);
        if (slot + sizeof(std::uint64_t) > image_size) break;
        std::memcpy(&callback, image + slot, sizeof(callback));
        if (!callback) break;

        const auto target = base + static_cast<std::uintptr_t>(callback - preferred);
        std::uintptr_t ignored = 0;
        hijack_call(proc, target, base, 1, 0, &ignored);
        std::fprintf(stderr, "[trace] callback TLS %zu appele\n", i);
    }
    return true;
}

bool apply_imports(HANDLE proc, std::uintptr_t base, const std::uint8_t* image,                   std::size_t image_size) {
    const auto* imports = directory(image, image_size, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (!imports || !imports->Size) return true;
    if (static_cast<std::size_t>(imports->VirtualAddress) + sizeof(IMAGE_IMPORT_DESCRIPTOR) > image_size)
        return false;

    const auto* descriptor = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
        image + imports->VirtualAddress);

    for (; descriptor->Name; ++descriptor) {
        if (descriptor->Name >= image_size) return false;

        const auto* module_name = reinterpret_cast<const char*>(image + descriptor->Name);
        wchar_t wide[128]{};
        MultiByteToWideChar(CP_ACP, 0, module_name, -1, wide, 128);

        std::uintptr_t module = remote_module_base(proc, wide);

        if (!module) {
            const char* host = remap_apiset(module_name);
            if (host) {
                wchar_t host_wide[128]{};
                MultiByteToWideChar(CP_ACP, 0, host, -1, host_wide, 128);
                module = remote_module_base(proc, host_wide);
                if (module) std::fprintf(stderr, "[trace] remap %s -> %s\n", module_name, host);
            }
        }

        if (!module) {
            std::fprintf(stderr, "[trace] chargement distant : %s\n", module_name);
            if (!load_remote(proc, wide, module) && !g_dll_dir.empty()) {
                const auto full = (g_dll_dir / module_name).wstring();
                std::fprintf(stderr, "[trace] essai par chemin: %ls\n", full.c_str());
                load_remote(proc, full.c_str(), module);
            }
        }

        if (!module) {
            std::fprintf(stderr, "[trace] module introuvable : %s\n", module_name);
            return false;
        }

        if (descriptor->FirstThunk >= image_size) return false;

        const auto* thunk = reinterpret_cast<const IMAGE_THUNK_DATA64*>(
            image + descriptor->FirstThunk);
        std::uintptr_t slot = base + descriptor->FirstThunk;

        for (; thunk->u1.AddressOfData; ++thunk, slot += sizeof(std::uint64_t)) {
            std::uintptr_t resolved = 0;

            if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                resolved = resolve_export(proc, module, nullptr,
                                          static_cast<std::uint16_t>(thunk->u1.Ordinal & 0xFFFF));
            } else {
                const auto* by_name = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
                    image + thunk->u1.AddressOfData);
                resolved = resolve_export(proc, module,
                                          reinterpret_cast<const char*>(by_name->Name), 0);
            }

            if (!resolved) return false;
            if (!write_value(proc, slot, resolved)) return false;
        }
    }
    return true;
}

}

MapResult manual_map(const ProcessHandle& proc, const std::filesystem::path& dll,
                     bool wipe_headers) {
    MapResult result;
    g_dll_dir = dll.parent_path();
    result.stage = "lecture";

    const auto file = read_file(dll);
    if (file.size() < sizeof(IMAGE_DOS_HEADER)) { result.error = "fichier illisible"; return result; }

    std::vector<std::uint8_t> image;
    result.stage = "image";
    if (!build_local_image(file, image)) { result.error = "image PE invalide"; return result; }

    std::fprintf(stderr, "[trace] fichier %zu, image %zu\n", file.size(), image.size());

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image.data() + dos->e_lfanew);
    const auto preferred = static_cast<std::uintptr_t>(nt->OptionalHeader.ImageBase);

    result.stage = "allocation";
    const std::uintptr_t base = alloc_mem(proc.handle, image.size(), PAGE_READWRITE);
    if (!base) { result.error = "allocation distante refusee"; return result; }
    result.base = base;
    std::fprintf(stderr, "[trace] allocation 0x%llX\n", (unsigned long long)base);

    result.stage = "ecriture";
    if (!write_mem(proc.handle, base, image.data(), image.size())) {
        result.error = "ecriture de l'image echouee"; return result;
    }

    if (base != preferred) {
        result.stage = "relocations";
        const auto delta = static_cast<std::int64_t>(base) - static_cast<std::int64_t>(preferred);
        if (!apply_relocations(proc.handle, base, image.data(), image.size(), delta)) {
            result.error = "relocations echouees"; return result;
        }
    }

    result.stage = "imports";
    if (!apply_imports(proc.handle, base, image.data(), image.size())) {
        result.error = "resolution d'imports echouee"; return result;
    }
    std::fprintf(stderr, "[trace] imports ok\n");
    if (!patch_pc_to_file_header(proc.handle, base, image.data(), image.size())) return result;

    result.stage = "tls";
    if (!register_exceptions(proc.handle, base, image.data(), image.size())) {
        result.error = "enregistrement des exceptions echoue"; return result;
    }
    if (!run_tls(proc.handle, base, preferred, image.data(), image.size())) {
        result.error = "initialisation TLS echouee"; return result;
    }

    result.stage = "protections";
    auto* section = IMAGE_FIRST_SECTION(nt);
    for (std::size_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        if (!section->SizeOfRawData) continue;

        DWORD protection = PAGE_READONLY;
        if (section->Characteristics & IMAGE_SCN_MEM_WRITE) protection = PAGE_READWRITE;
        else if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) protection = PAGE_EXECUTE_READ;

        DWORD previous = 0;
        protect_mem(proc.handle, base + section->VirtualAddress,
                    section->SizeOfRawData, protection, &previous);
    }

    std::fprintf(stderr, "[trace] entree rva=0x%X base=0x%llX", nt->OptionalHeader.AddressOfEntryPoint, (unsigned long long)base); std::fprintf(stderr, "\n");
    result.stage = "hijack";
    std::uintptr_t veh_report = 0;
    {
        const auto add_veh = reinterpret_cast<std::uintptr_t>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlAddVectoredExceptionHandler"));
        veh_report = alloc_mem(proc.handle, 0x40, PAGE_READWRITE);

        std::vector<std::uint8_t> handler;
        auto imm = [&](std::uintptr_t value) {
            handler.push_back(0x48); handler.push_back(0xB8);
            const auto* p = reinterpret_cast<const std::uint8_t*>(&value);
            handler.insert(handler.end(), p, p + sizeof(value));
        };
        // magic
        imm(veh_report); handler.push_back(0xC7); handler.push_back(0x00);
        handler.push_back(0xEF); handler.push_back(0xBE); handler.push_back(0xAD); handler.push_back(0xDE);
        // exception record
        handler.push_back(0x48); handler.push_back(0x8B); handler.push_back(0x11);
        imm(veh_report + 32); handler.push_back(0x48); handler.push_back(0x89); handler.push_back(0x10);
        // context
        const std::uint8_t a[] = { 0x48, 0x8B, 0x41, 0x08, 0x48, 0x8B, 0x90, 0xF8, 0x00, 0x00, 0x00 };
        handler.insert(handler.end(), a, a + sizeof(a));
        imm(veh_report + 8); handler.push_back(0x48); handler.push_back(0x89); handler.push_back(0x10);
        // code
        const std::uint8_t c[] = { 0x48, 0x8B, 0x01, 0x8B, 0x00 };
        handler.insert(handler.end(), c, c + sizeof(c));
        imm(veh_report + 16); handler.push_back(0x89); handler.push_back(0x00);
        handler.push_back(0x48); handler.push_back(0x8B); handler.push_back(0x41); handler.push_back(0x08);
        handler.push_back(0x48); handler.push_back(0x8B); handler.push_back(0x90);
        handler.push_back(0x98); handler.push_back(0x00); handler.push_back(0x00); handler.push_back(0x00);
        imm(veh_report + 24); handler.push_back(0x48); handler.push_back(0x89); handler.push_back(0x10);
        const std::uint8_t z[] = { 0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3 };
        handler.insert(handler.end(), z, z + sizeof(z));

        const auto buffer = alloc_mem(proc.handle, handler.size(), PAGE_EXECUTE_READWRITE);
        if (buffer && add_veh) {
            write_mem(proc.handle, buffer, handler.data(), handler.size());
            std::uintptr_t ignored = 0;
            hijack_call(proc.handle, add_veh, 1, buffer, 0, &ignored);
            std::fprintf(stderr, "[trace] veh installe\n");
        }
    }

    auto hijack = hijack_thread(proc.handle, base, base + nt->OptionalHeader.AddressOfEntryPoint);
    if (!hijack.done) {
        std::uint32_t magic = 0, fault_code = 0, fault_flags = 0, fault_params = 0;
        std::uintptr_t fault_rip = 0, fault_addr = 0, er = 0, info0 = 0, info1 = 0;
        if (veh_report) {
            read_value(proc.handle, veh_report, magic);
            read_value(proc.handle, veh_report + 8, fault_rip);
            read_value(proc.handle, veh_report + 32, er);
            if (er) {
                read_value(proc.handle, er, fault_code);
                read_value(proc.handle, er + 0x04, fault_flags);
                read_value(proc.handle, er + 0x10, fault_addr);
                read_value(proc.handle, er + 0x18, fault_params);
                read_value(proc.handle, er + 0x20, info0);
                read_value(proc.handle, er + 0x28, info1);
            }
        }
        unsigned char entry_bytes[16]{};
        read_mem(proc.handle, base + nt->OptionalHeader.AddressOfEntryPoint, entry_bytes, sizeof(entry_bytes));
        std::fprintf(stderr, "[trace] entree:");
        for (unsigned char b : entry_bytes) std::fprintf(stderr, " %02X", b);
        std::fprintf(stderr, "\n");
        auto nearest_name = [&](std::uintptr_t module, std::uintptr_t address) -> std::wstring {
            IMAGE_DOS_HEADER dos{};
            if (!read_value(proc.handle, module, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) return L"";
            IMAGE_NT_HEADERS64 nt2{};
            if (!read_value(proc.handle, module + dos.e_lfanew, nt2)) return L"";

            const auto& dir = nt2.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (!dir.VirtualAddress) return L"";

            IMAGE_EXPORT_DIRECTORY ex{};
            if (!read_value(proc.handle, module + dir.VirtualAddress, ex)) return L"";
            if (!ex.NumberOfFunctions || !ex.NumberOfNames) return L"";

            std::vector<std::uint32_t> funcs(ex.NumberOfFunctions);
            if (!read_mem(proc.handle, module + ex.AddressOfFunctions,
                          funcs.data(), funcs.size() * sizeof(std::uint32_t))) return L"";

            const auto target_rva = static_cast<std::uint32_t>(address - module);
            std::size_t best = funcs.size();
            for (std::size_t i = 0; i < funcs.size(); ++i)
                if (funcs[i] && funcs[i] <= target_rva && (best == funcs.size() || funcs[i] > funcs[best]))
                    best = i;
            if (best == funcs.size()) return L"";

            std::vector<std::uint32_t> names(ex.NumberOfNames);
            std::vector<std::uint16_t> ordinals(ex.NumberOfNames);
            if (!read_mem(proc.handle, module + ex.AddressOfNames,
                          names.data(), names.size() * sizeof(std::uint32_t))) return L"";
            if (!read_mem(proc.handle, module + ex.AddressOfNameOrdinals,
                          ordinals.data(), ordinals.size() * sizeof(std::uint16_t))) return L"";

            for (std::size_t i = 0; i < names.size(); ++i) {
                if (ordinals[i] != best) continue;
                char buffer[200]{};
                if (!read_mem(proc.handle, module + names[i], buffer, sizeof(buffer) - 1)) continue;
                wchar_t wide[200]{};
                MultiByteToWideChar(CP_ACP, 0, buffer, -1, wide, 200);
                wchar_t out[260];
                swprintf_s(out, L"%s+0x%X", wide, target_rva - funcs[best]);
                return out;
            }
            return L"";
        };

        auto nearest_name2 = [&](std::uintptr_t module, std::uintptr_t address) -> std::wstring {
            IMAGE_DOS_HEADER dos{};
            if (!read_value(proc.handle, module, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) return L"";
            IMAGE_NT_HEADERS64 nt2{};
            if (!read_value(proc.handle, module + dos.e_lfanew, nt2)) return L"";

            const auto& dir = nt2.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (!dir.VirtualAddress) return L"";

            IMAGE_EXPORT_DIRECTORY ex{};
            if (!read_value(proc.handle, module + dir.VirtualAddress, ex)) return L"";
            if (!ex.NumberOfFunctions || !ex.NumberOfNames) return L"";

            std::vector<std::uint32_t> funcs(ex.NumberOfFunctions);
            if (!read_mem(proc.handle, module + ex.AddressOfFunctions,
                          funcs.data(), funcs.size() * sizeof(std::uint32_t))) return L"";

            const auto target_rva = static_cast<std::uint32_t>(address - module);
            std::size_t best = funcs.size();
            for (std::size_t i = 0; i < funcs.size(); ++i)
                if (funcs[i] && funcs[i] <= target_rva && (best == funcs.size() || funcs[i] > funcs[best]))
                    best = i;
            if (best == funcs.size()) return L"";

            std::vector<std::uint32_t> names(ex.NumberOfNames);
            std::vector<std::uint16_t> ordinals(ex.NumberOfNames);
            if (!read_mem(proc.handle, module + ex.AddressOfNames,
                          names.data(), names.size() * sizeof(std::uint32_t))) return L"";
            if (!read_mem(proc.handle, module + ex.AddressOfNameOrdinals,
                          ordinals.data(), ordinals.size() * sizeof(std::uint16_t))) return L"";

            for (std::size_t i = 0; i < names.size(); ++i) {
                if (ordinals[i] != best) continue;
                char buffer[200]{};
                if (!read_mem(proc.handle, module + names[i], buffer, sizeof(buffer) - 1)) continue;
                wchar_t wide[200]{};
                MultiByteToWideChar(CP_ACP, 0, buffer, -1, wide, 200);
                wchar_t out[260];
                swprintf_s(out, L"%s+0x%X", wide, target_rva - funcs[best]);
                return out;
            }
            return L"";
        };

        auto describe = [&](std::uintptr_t address) -> std::wstring {
            const auto snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, proc.pid);
            if (snap == INVALID_HANDLE_VALUE) return L"?";
            std::wstring out = L"?";
            MODULEENTRY32W me{}; me.dwSize = sizeof(me);
            if (Module32FirstW(snap, &me)) {
                do {
                    const auto mb = reinterpret_cast<std::uintptr_t>(me.modBaseAddr);
                    if (address >= mb && address < mb + me.modBaseSize) {
                        const auto named = nearest_name(mb, address);
                        wchar_t raw[200];
                        swprintf_s(raw, L"%s+0x%llX", me.szModule, (unsigned long long)(address - mb));
                        out = named.empty() ? std::wstring(raw) : (std::wstring(named) + L" [" + raw + L"]");
                        break;
                    }
                } while (Module32NextW(snap, &me));
            }
            CloseHandle(snap);
            return out;
        };        std::fprintf(stderr, "[trace] magic=0x%X code=0x%08X flags=0x%X addr=0x%llX nparams=%u\n",
                     magic, fault_code, fault_flags, (unsigned long long)fault_addr, fault_params);
        std::fprintf(stderr, "[trace] info0=0x%llX info1=0x%llX rip=%ls entree=0x%llX\n",
                     (unsigned long long)info0, (unsigned long long)info1,
                     describe(fault_rip).c_str(),
                     (unsigned long long)(base + nt->OptionalHeader.AddressOfEntryPoint));

        std::uintptr_t fault_rsp = 0;
        read_value(proc.handle, veh_report + 24, fault_rsp);
        std::fprintf(stderr, "[trace] rsp=0x%llX\n", (unsigned long long)fault_rsp);
        if (fault_rsp) {
            std::uintptr_t frames[10]{};
            read_mem(proc.handle, fault_rsp, frames, sizeof(frames));
            for (std::uintptr_t frame : frames) {
                if (frame) std::fprintf(stderr, "[trace]   pile: %ls\n", describe(frame).c_str());
            }
        }
        result.error = "DllMain n'a pas rendu la main"; return result;
    }
    std::fprintf(stderr, "[trace] dllmain rendu la main\n");

    unlink_from_peb(proc.handle, hijack.thread, base);
    std::fprintf(stderr, "[trace] unlink peb fait\n");

    if (wipe_headers) {
        std::vector<std::uint8_t> zeros(nt->OptionalHeader.SizeOfHeaders, 0);
        write_mem(proc.handle, base, zeros.data(), zeros.size());
    }

    Sleep(150);
    result.stage = "ok";
    result.ok = true;
    return result;
}

}















