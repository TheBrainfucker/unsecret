#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string_view>
#include <vector>

#include "unsecret/finding.hpp"
#include "unsecret/keyword_filter.hpp"
#include "unsecret/rule.hpp"

namespace unsecret {

struct ScanResult {
    std::vector<Finding> findings;
    std::size_t files_scanned = 0;
    std::uintmax_t bytes_scanned = 0;
    std::size_t skipped_binary = 0;
    std::size_t skipped_large = 0;
    std::vector<std::filesystem::path> unreadable;  // a warning, not an error
};

// A NUL byte in the first 8 KB.
bool looks_binary(std::string_view content);

class Scanner {
public:
    static constexpr std::uintmax_t default_max_file_size = 1024 * 1024;

    // Long lines are scanned in overlapping pieces. The overlap must be longer than any match.
    static constexpr std::size_t window_size = 4096;
    static constexpr std::size_t window_overlap = 2560;

    explicit Scanner(std::uintmax_t max_file_size = default_max_file_size);

    // At most 64 rules.
    void add_rule(std::unique_ptr<Rule> rule);

    // On by default. Off is for tests and the benchmark.
    void use_prefilter(bool on) { prefilter_ = on; }

    // A file or a folder. Throws if `root` can't be read at all.
    ScanResult scan(const std::filesystem::path& root) const;

    void scan_text(std::string_view text, const std::filesystem::path& file,
                   std::vector<Finding>& out) const;

private:
    void scan_file(const std::filesystem::path& file, const std::filesystem::path& display,
                   std::uintmax_t size, ScanResult& result) const;
    void scan_line(std::string_view line, std::size_t line_number,
                   const std::filesystem::path& file, std::vector<Finding>& out) const;

    std::uintmax_t max_file_size_;
    std::vector<std::unique_ptr<Rule>> rules_;
    KeywordFilter filter_;
    std::uint64_t always_run_ = 0;  // rules without keywords
    bool prefilter_ = true;
};

}  // namespace unsecret
