#pragma once

#include <filesystem>
#include <memory>
#include <vector>

#include "unsecret/finding.hpp"
#include "unsecret/rule.hpp"

namespace unsecret {

// Walks files and runs every registered rule on every line.
class Scanner {
public:
    void add_rule(std::unique_ptr<Rule> rule);

    // Scan a single file or a whole directory tree.
    std::vector<Finding> scan(const std::filesystem::path& root) const;

private:
    std::vector<Finding> scan_file(const std::filesystem::path& file) const;
    static bool looks_binary(const std::filesystem::path& file);

    std::vector<std::unique_ptr<Rule>> rules_;
};

}  // namespace unsecret
