#pragma once
#include <windows.h>
#include <cstdint>

namespace lunar::injector {

bool unlink_from_peb(HANDLE proc, HANDLE thread, std::uintptr_t module_base);

}
