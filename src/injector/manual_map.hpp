#pragma once
#include "process.hpp"
#include <filesystem>
#include <string>

namespace lunar::injector {

struct MapResult {
    bool ok = false;
    std::uintptr_t base = 0;
    std::string error;
    std::string stage;

    explicit operator bool() const { return ok; }
};

MapResult manual_map(const ProcessHandle& proc, const std::filesystem::path& dll, bool wipe_headers);

}

