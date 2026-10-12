#include "unsecret/scanner.hpp"

#include <fstream>
#include <optional>
#include <string>
#include <system_error>
#include <utility>

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

}  // namespace

bool looks_binary(std::string_view content) {
    return content.substr(0, binary_sniff_size).find('\0') != std::string_view::npos;
}

Scanner::Scanner(std::uintmax_t max_file_size) : max_file_size_(max_file_size) {}

void Scanner::add_rule(std::unique_ptr<Rule> rule) {
    rules_.push_back(std::move(rule));
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

    fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec);
    const fs::recursive_directory_iterator end;

    // If the walk breaks, throw: a half scan must not look clean.
    for (; !ec && it != end; it.increment(ec)) {
        const fs::directory_entry& entry = *it;
        std::error_code entry_ec;

        // Links can leave the folder or loop.
        if (entry.is_symlink(entry_ec)) {
            continue;
        }
        if (entry.is_directory(entry_ec)) {
            if (entry.path().filename() == ".git") {
                it.disable_recursion_pending();
            }
            continue;
        }
        if (!entry.is_regular_file(entry_ec)) {
            continue;
        }

        const auto size = entry.file_size(entry_ec);
        if (entry_ec) {
            result.unreadable.push_back(entry.path().lexically_relative(root));
            continue;
        }
        scan_file(entry.path(), entry.path().lexically_relative(root), size, result);
    }
    if (ec) {
        throw fs::filesystem_error("cannot walk directory", root, ec);
    }
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

        for (const auto& rule : rules_) {
            for (const auto& match : rule->find(window)) {
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
        if (last) {
            break;
        }
    }
}

}  // namespace unsecret
