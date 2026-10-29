#include <windows.h>
#include <cstddef>

namespace lunar::hyperion {

// Snapshot des pages .text avant modification. A implementer.
bool snapshot_pages(void* base, std::size_t size) {
    (void)base; (void)size;
    return true;
}

}
