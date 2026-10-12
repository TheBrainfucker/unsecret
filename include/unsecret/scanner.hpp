#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string_view>
#include <vector>

#include "unsecret/finding.hpp"
#include "unsecret/rule.hpp"

namespace unsecret {

// Everything one scan produced: the findings plus what was (not) looked at,
// so the summary line can say how much of the tree was actually covered.
struct ScanResult {
    std::vector<Finding> findings;
    std::size_t files_scanned = 0;
    std::size_t skipped_binary = 0;
    std::size_t skipped_large = 0;
    std::vector<std::filesystem::path> unreadable;  // reported as warnings, not errors
};

// True if the first 8 KB contain a NUL byte, the usual sign of a binary file.
bool looks_binary(std::string_view content);

// Walks files and runs every registered rule on every line.
class Scanner {
public:
    static constexpr std::uintmax_t default_max_file_size = 1024 * 1024;

    explicit Scanner(std::uintmax_t max_file_size = default_max_file_size);

    void add_rule(std::unique_ptr<Rule> rule);

    // Scan a single file or a whole directory tree. `.git` directories are skipped.
    // Paths in the result are relative to `root` when `root` is a directory.
    // Throws std::filesystem::filesystem_error if `root` cannot be scanned at all.
    ScanResult scan(const std::filesystem::path& root) const;

    // Run every rule on every line of `text` and append the findings, using `file`
    // as the path to report. Handles a UTF-8 BOM and both LF and CRLF line endings.
    void scan_text(std::string_view text, const std::filesystem::path& file,
                   std::vector<Finding>& out) const;

private:
    void scan_file(const std::filesystem::path& file, const std::filesystem::path& display,
                   std::uintmax_t size, ScanResult& result) const;

    std::uintmax_t max_file_size_;
    std::vector<std::unique_ptr<Rule>> rules_;
};

}  // namespace unsecret
