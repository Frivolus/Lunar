#include "manual_map.hpp"
#include "remote.hpp"
#include "peb.hpp"
#include "thread_hijack.hpp"
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <fstream>
#include <vector>

namespace lunar::injector {
namespace {

constexpr std::size_t kMaxImage = 256u * 1024u * 1024u;

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
        }

        offset += block->SizeOfBlock;
    }
    return true;
}

std::uintptr_t resolve_export(HANDLE proc, std::uintptr_t module,
                              const char* name, std::uint16_t ordinal_hint) {
    if (!module) return 0;

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

    std::vector<std::uint32_t> funcs(dir.NumberOfFunctions);
    if (!read_mem(proc, module + dir.AddressOfFunctions,
                  funcs.data(), funcs.size() * sizeof(std::uint32_t))) return 0;

    if (!name) {
        const auto index = static_cast<std::size_t>(ordinal_hint - dir.Base);
        if (index >= funcs.size()) return 0;
        return module + funcs[index];
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
        return module + funcs[ordinals[i]];
    }
    return 0;
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

bool apply_imports(HANDLE proc, std::uintptr_t base, const std::uint8_t* image,
                   std::size_t image_size) {
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
            load_remote(proc, wide, module);
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

    result.stage = "hijack";
    auto hijack = hijack_thread(proc.handle, base, base + nt->OptionalHeader.AddressOfEntryPoint);
    if (!hijack) { result.error = "hijack de thread echoue"; return result; }
    if (!hijack.done) { result.error = "DllMain n'a pas rendu la main"; return result; }
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
