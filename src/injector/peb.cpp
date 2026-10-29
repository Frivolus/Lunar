#include "peb.hpp"
#include "remote.hpp"
#include "ntdll.hpp"

namespace lunar::injector {
namespace {

constexpr std::uintptr_t kTebPeb = 0x60;
constexpr std::uintptr_t kPebLdr = 0x18;
constexpr std::uintptr_t kLdrLoadList = 0x10;
constexpr std::uintptr_t kEntryLoad = 0x00;
constexpr std::uintptr_t kEntryMem = 0x10;
constexpr std::uintptr_t kEntryInit = 0x20;
constexpr std::uintptr_t kEntryBase = 0x30;

bool unlink_pair(HANDLE proc, std::uintptr_t links) {
    std::uintptr_t flink = 0;
    std::uintptr_t blink = 0;
    if (!read_value(proc, links, flink)) return false;
    if (!read_value(proc, links + 0x08, blink)) return false;
    if (!write_value<std::uintptr_t>(proc, blink, flink)) return false;
    if (!write_value<std::uintptr_t>(proc, flink + 0x08, blink)) return false;
    return true;
}

}

bool unlink_from_peb(HANDLE proc, HANDLE thread, std::uintptr_t module_base) {
    nt::ThreadBasicInformation tbi{};
    if (nt::api().query_information_thread(thread, nt::kThreadBasicInformation,
                                           &tbi, sizeof(tbi), nullptr) < 0)
        return false;

    const auto teb = reinterpret_cast<std::uintptr_t>(tbi.teb_base);
    if (!teb) return false;

    std::uintptr_t peb = 0;
    if (!read_value(proc, teb + kTebPeb, peb) || !peb) return false;

    std::uintptr_t ldr = 0;
    if (!read_value(proc, peb + kPebLdr, ldr) || !ldr) return false;

    const std::uintptr_t head = ldr + kLdrLoadList;
    std::uintptr_t cursor = 0;
    if (!read_value(proc, head, cursor)) return false;

    for (int guard = 0; cursor && cursor != head && guard < 512; ++guard) {
        std::uintptr_t base = 0;
        if (!read_value(proc, cursor + kEntryBase, base)) return false;

        if (base == module_base) {
            unlink_pair(proc, cursor + kEntryLoad);
            unlink_pair(proc, cursor + kEntryMem);
            unlink_pair(proc, cursor + kEntryInit);
            return true;
        }

        if (!read_value(proc, cursor, cursor)) return false;
    }
    return false;
}

}
