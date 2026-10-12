#include "unsecret/report.hpp"

#include <cstdio>
#include <set>

namespace unsecret {

namespace {

std::string count(std::size_t n, std::string_view word) {
    return std::to_string(n) + " " + std::string(word) + (n == 1 ? "" : "s");
}

std::string size_text(std::uintmax_t bytes) {
    if (bytes < 1024) {
        return count(static_cast<std::size_t>(bytes), "byte");
    }
    char text[32];
    const double kb = static_cast<double>(bytes) / 1024.0;
    if (kb < 1024.0) {
        std::snprintf(text, sizeof text, "%.1f KB", kb);
    } else {
        std::snprintf(text, sizeof text, "%.1f MB", kb / 1024.0);
    }
    return text;
}

}  // namespace

std::string mask(std::string_view secret) {
    const std::string stars = "********";
    if (secret.size() < 16) {
        return stars;
    }
    return std::string(secret.substr(0, 4)) + stars;
}

void print_report(const ScanResult& result, std::ostream& out, std::ostream& summary) {
    for (const auto& f : result.findings) {
        out << f.file.generic_string() << ':' << f.line << ':' << f.column << " [" << f.rule_id
            << "] " << mask(f.match) << '\n';
    }
    for (const auto& file : result.unreadable) {
        summary << "warning: could not read " << file.generic_string() << '\n';
    }

    std::set<std::filesystem::path> files;
    for (const auto& f : result.findings) {
        files.insert(f.file);
    }
    if (result.findings.empty()) {
        summary << "no findings";
    } else {
        summary << count(result.findings.size(), "finding") << " in " << count(files.size(), "file");
    }
    summary << " (scanned " << count(result.files_scanned, "file") << ", "
            << size_text(result.bytes_scanned);

    std::string skipped;
    auto add = [&](std::size_t n, std::string_view what) {
        if (n > 0) {
            skipped += (skipped.empty() ? "" : ", ") + std::to_string(n) + " " + std::string(what);
        }
    };
    add(result.skipped_binary, "binary");
    add(result.skipped_large, "too large");
    add(result.skipped_ignored, "ignored");
    add(result.unreadable.size(), "unreadable");
    if (!skipped.empty()) {
        summary << "; skipped " << skipped;
    }
    summary << ")\n";
}

}  // namespace unsecret
