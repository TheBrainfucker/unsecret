#pragma once

#include <cstddef>
#include <filesystem>
#include <string>

namespace unsecret {

struct Finding {
    std::filesystem::path file;  // relative to the scanned folder
    std::size_t line = 0;      // starts at 1
    std::size_t column = 0;    // starts at 1, in bytes
    std::string rule_id;
    std::string match;         // the real secret: mask before printing

    bool operator==(const Finding&) const = default;
};

}  // namespace unsecret
