#include "manual_map.hpp"
#include "remote.hpp"
#include "peb.hpp"
#include "thread_hijack.hpp"
#include <cstring>
#include <fstream>
#include <vector>

namespace lunar::injector {
namespace {

std::vector<std::uint8_t> read_file(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) return {};
    const auto size = static_cast<std::size_t>(stream.tellg());
    stream.seekg(0);
    std::vector<std::uint8_t> buffer(size);
    stream.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(size));
    return buffer;
}

const IMAGE_DATA_DIRECTORY* directory(const std::uint8_t* image, std::size_t index) {
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image + dos->e_lfanew);
    return &nt->OptionalHeader.DataDirectory[index];
}

bool apply_relocations(HANDLE proc, std::uintptr_t base, const std::uint8_t* image,
                       std::int64_t delta) {
    const auto* reloc = directory(image, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (!reloc || !reloc->Size) return true;

    std::size_t offset = 0;
    while (offset + sizeof(IMAGE_BASE_RELOCATION) <= reloc->Size) {
        const auto* block = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(
            image + reloc->VirtualAddress + offset);
        if (!block->SizeOfBlock) break;

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

bool apply_imports(HANDLE proc, std::uintptr_t base, const std::uint8_t* image) {
    const auto* imports = directory(image, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (!imports || !imports->Size) return true;

    const auto* descriptor = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
        image + imports->VirtualAddress);

    for (; descriptor->Name; ++descriptor) {
        const auto* module_name = reinterpret_cast<const char*>(image + descriptor->Name);
        wchar_t wide[128]{};
        MultiByteToWideChar(CP_ACP, 0, module_name, -1, wide, 128);

        const auto module = remote_module_base(ProcessHandle{ proc, GetProcessId(proc) }, wide);
        if (!module) return false;

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

    const auto image = read_file(dll);
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) { result.error = "fichier illisible"; return result; }

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { result.error = "signature DOS invalide"; return result; }

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { result.error = "signature NT invalide"; return result; }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) { result.error = "cible non x64"; return result; }

    const auto size = static_cast<std::size_t>(nt->OptionalHeader.SizeOfImage);
    const auto preferred = static_cast<std::uintptr_t>(nt->OptionalHeader.ImageBase);

    const std::uintptr_t base = alloc_mem(proc.handle, size, PAGE_READWRITE);
    if (!base) { result.error = "allocation distante refusee"; return result; }
    result.base = base;

    if (!write_mem(proc.handle, base, image.data(), nt->OptionalHeader.SizeOfHeaders)) {
        result.error = "ecriture des en-tetes echouee"; return result;
    }

    auto* section = IMAGE_FIRST_SECTION(nt);
    for (std::size_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        if (!section->SizeOfRawData) continue;
        if (!write_mem(proc.handle, base + section->VirtualAddress,
                       image.data() + section->PointerToRawData, section->SizeOfRawData)) {
            result.error = "ecriture de section echouee"; return result;
        }
    }

    if (base != preferred) {
        const auto delta = static_cast<std::int64_t>(base) - static_cast<std::int64_t>(preferred);
        if (!apply_relocations(proc.handle, base, image.data(), delta)) {
            result.error = "relocations echouees"; return result;
        }
    }

    if (!apply_imports(proc.handle, base, image.data())) {
        result.error = "resolution d'imports echouee"; return result;
    }

    section = IMAGE_FIRST_SECTION(nt);
    for (std::size_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        if (!section->SizeOfRawData) continue;

        DWORD protection = PAGE_READONLY;
        if (section->Characteristics & IMAGE_SCN_MEM_WRITE) protection = PAGE_READWRITE;
        else if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) protection = PAGE_EXECUTE_READ;

        DWORD previous = 0;
        protect_mem(proc.handle, base + section->VirtualAddress,
                    section->SizeOfRawData, protection, &previous);
    }

    auto hijack = hijack_thread(proc.handle, base, base + nt->OptionalHeader.AddressOfEntryPoint);
    if (!hijack) { result.error = "hijack de thread echoue"; return result; }
    if (!hijack.done) { result.error = "DllMain n'a pas rendu la main"; return result; }

    unlink_from_peb(proc.handle, hijack.thread, base);

    if (wipe_headers) {
        std::vector<std::uint8_t> zeros(nt->OptionalHeader.SizeOfHeaders, 0);
        write_mem(proc.handle, base, zeros.data(), zeros.size());
    }

    result.ok = true;
    return result;
}

}
