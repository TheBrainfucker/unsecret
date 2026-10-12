#pragma once

#include <cstddef>
#include <filesystem>
#include <string>

namespace unsecret {

// One suspected secret found in a file.
struct Finding {
    std::filesystem::path file;
    std::size_t line = 0;      // 1-based line number
    std::string rule_id;       // which rule fired, e.g. "aws-access-key-id"
    std::string match;         // the raw matched text (mask before printing!)
};

}  // namespace unsecret
