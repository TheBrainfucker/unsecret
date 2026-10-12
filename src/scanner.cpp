#include "unsecret/scanner.hpp"

#include <algorithm>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <tuple>
#include <utility>

#include "unsecret/ignore_list.hpp"

namespace fs = std::filesystem;

namespace unsecret {

namespace {

constexpr std::size_t binary_sniff_size = 8 * 1024;
constexpr std::string_view utf8_bom = "\xEF\xBB\xBF";

// Binary mode: keep \r\n as is on Windows.
std::optional<std::string> read_file(const fs::path& file, std::uintmax_t size) {
    std::ifstream in(file, std::ios::binary);
    if (!in) {
        return std::nullopt;
    }
    std::string content(static_cast<std::size_t>(size), '\0');
    in.read(content.data(), static_cast<std::streamsize>(content.size()));
    if (in.bad()) {
        return std::nullopt;
    }
    content.resize(static_cast<std::size_t>(in.gcount()));
    return content;
}

bool overlaps_any(const Match& m, const std::vector<Match>& others) {
    for (const auto& o : others) {
        if (m.pos < o.pos + o.len && o.pos < m.pos + m.len) {
            return true;
        }
    }
    return false;
}

}  // namespace

bool looks_binary(std::string_view content) {
    return content.substr(0, binary_sniff_size).find('\0') != std::string_view::npos;
}

Scanner::Scanner(std::uintmax_t max_file_size) : max_file_size_(max_file_size) {}

void Scanner::add_rule(std::unique_ptr<Rule> rule) {
    if (rules_.size() == KeywordFilter::max_groups) {
        throw std::length_error("too many rules");
    }
    rules_.push_back(std::move(rule));

    std::vector<std::pair<std::string, std::size_t>> keywords;
    always_run_ = 0;
    for (std::size_t i = 0; i < rules_.size(); ++i) {
        const auto rule_keywords = rules_[i]->keywords();
        if (rule_keywords.empty()) {
            always_run_ |= std::uint64_t{1} << i;
        }
        for (const auto& k : rule_keywords) {
            keywords.emplace_back(k, i);
        }
    }
    filter_ = KeywordFilter(keywords);
}

ScanResult Scanner::scan(const fs::path& root) const {
    ScanResult result;
    std::error_code ec;

    if (fs::is_regular_file(root, ec)) {
        const auto size = fs::file_size(root, ec);
        if (ec) {
            throw fs::filesystem_error("cannot read file", root, ec);
        }
        scan_file(root, root, size, result);
        return result;
    }
    if (!fs::is_directory(root, ec)) {
        if (!ec) {
            ec = std::make_error_code(std::errc::no_such_file_or_directory);
        }
        throw fs::filesystem_error("cannot scan", root, ec);
    }

    const auto ignore = IgnoreList::load(root / ignore_file_name);
    fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec);
    const fs::recursive_directory_iterator end;

    // If the walk breaks, throw: a half scan must not look clean.
    for (; !ec && it != end; it.increment(ec)) {
        const fs::directory_entry& entry = *it;
        const auto relative = entry.path().lexically_relative(root);
        std::error_code entry_ec;

        // Links can leave the folder or loop.
        if (entry.is_symlink(entry_ec)) {
            continue;
        }
        if (entry.is_directory(entry_ec)) {
            if (entry.path().filename() == ".git") {
                it.disable_recursion_pending();
            } else if (ignore.ignores(relative.generic_string(), true)) {
                it.disable_recursion_pending();
                ++result.skipped_ignored;
            }
            continue;
        }
        if (!entry.is_regular_file(entry_ec)) {
            continue;
        }
        if (ignore.ignores(relative.generic_string(), false)) {
            ++result.skipped_ignored;
            continue;
        }

        const auto size = entry.file_size(entry_ec);
        if (entry_ec) {
            result.unreadable.push_back(relative);
            continue;
        }
        scan_file(entry.path(), relative, size, result);
    }
    if (ec) {
        throw fs::filesystem_error("cannot walk directory", root, ec);
    }

    // Folder order differs between systems.
    std::sort(result.findings.begin(), result.findings.end(), [](const auto& a, const auto& b) {
        return std::tie(a.file, a.line, a.column, a.rule_id) <
               std::tie(b.file, b.line, b.column, b.rule_id);
    });
    std::sort(result.unreadable.begin(), result.unreadable.end());
    return result;
}

void Scanner::scan_file(const fs::path& file, const fs::path& display, std::uintmax_t size,
                        ScanResult& result) const {
    if (size > max_file_size_) {
        ++result.skipped_large;
        return;
    }
    const auto content = read_file(file, size);
    if (!content) {
        result.unreadable.push_back(display);
        return;
    }
    if (looks_binary(*content)) {
        ++result.skipped_binary;
        return;
    }
    ++result.files_scanned;
    result.bytes_scanned += content->size();
    scan_text(*content, display, result.findings);
}

void Scanner::scan_text(std::string_view text, const fs::path& file,
                        std::vector<Finding>& out) const {
    if (text.substr(0, utf8_bom.size()) == utf8_bom) {
        text.remove_prefix(utf8_bom.size());
    }

    std::size_t line_number = 0;
    std::size_t start = 0;
    while (start < text.size()) {
        auto end = text.find('\n', start);
        if (end == std::string_view::npos) {
            end = text.size();
        }
        auto line = text.substr(start, end - start);
        if (!line.empty() && line.back() == '\r') {
            line.remove_suffix(1);
        }
        ++line_number;
        scan_line(line, line_number, file, out);
        start = end + 1;
    }
}

void Scanner::scan_line(std::string_view line, std::size_t line_number, const fs::path& file,
                        std::vector<Finding>& out) const {
    // A piece keeps only hits that start before the next piece, so none is counted twice.
    constexpr std::size_t step = window_size - window_overlap;
    for (std::size_t offset = 0;; offset += step) {
        const auto window = line.substr(offset, window_size);
        const bool last = offset + window.size() >= line.size();
        const std::size_t keep_before = last ? window.size() : step;

        // Run a rule's regex only if one of its keywords is here.
        const auto to_run = prefilter_ ? (filter_.find(window) | always_run_) : ~std::uint64_t{0};

        // Normal rules first, so fallback hits can be checked against them.
        std::vector<Match> normal_hits;
        for (const bool fallback : {false, true}) {
            for (std::size_t i = 0; i < rules_.size(); ++i) {
                const auto& rule = rules_[i];
                if (rule->is_fallback() != fallback || ((to_run >> i) & 1) == 0) {
                    continue;
                }
                for (const auto& match : rule->find(window)) {
                    if (fallback && overlaps_any(match, normal_hits)) {
                        continue;
                    }
                    if (!fallback) {
                        normal_hits.push_back(match);
                    }
                    if (match.pos >= keep_before) {
                        continue;
                    }
                    out.push_back(Finding{
                        file,
                        line_number,
                        offset + match.pos + 1,
                        std::string(rule->id()),
                        std::string(window.substr(match.pos, match.len)),
                    });
                }
            }
        }
        if (last) {
            break;
        }
    }
}

}  // namespace unsecret
