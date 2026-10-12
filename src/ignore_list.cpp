#include "unsecret/ignore_list.hpp"

#include <fstream>
#include <sstream>
#include <system_error>

namespace fs = std::filesystem;

namespace unsecret {

namespace {

std::string_view trim(std::string_view s) {
    const auto first = s.find_first_not_of(" \t\r");
    if (first == std::string_view::npos) {
        return {};
    }
    const auto last = s.find_last_not_of(" \t\r");
    return s.substr(first, last - first + 1);
}

}  // namespace

bool glob_match(std::string_view pattern, std::string_view text) {
    while (!pattern.empty()) {
        if (pattern.substr(0, 2) == "**") {
            pattern.remove_prefix(2);
            // "**/" may also match no folder at all.
            if (!pattern.empty() && pattern[0] == '/' && glob_match(pattern.substr(1), text)) {
                return true;
            }
            for (std::size_t i = 0; i <= text.size(); ++i) {
                if (glob_match(pattern, text.substr(i))) {
                    return true;
                }
            }
            return false;
        }
        if (pattern[0] == '*') {
            pattern.remove_prefix(1);
            for (std::size_t i = 0; i <= text.size(); ++i) {
                if (glob_match(pattern, text.substr(i))) {
                    return true;
                }
                if (i < text.size() && text[i] == '/') {
                    break;
                }
            }
            return false;
        }
        if (text.empty()) {
            return false;
        }
        const bool same = pattern[0] == '?' ? text[0] != '/' : pattern[0] == text[0];
        if (!same) {
            return false;
        }
        pattern.remove_prefix(1);
        text.remove_prefix(1);
    }
    return text.empty();
}

IgnoreList::IgnoreList(std::string_view text) {
    while (!text.empty()) {
        const auto end = text.find('\n');
        auto line = trim(text.substr(0, end));
        text = end == std::string_view::npos ? std::string_view{} : text.substr(end + 1);

        if (line.empty() || line[0] == '#') {
            continue;
        }
        Pattern p;
        if (line.back() == '/') {
            p.folders_only = true;
            line.remove_suffix(1);
        }
        if (!line.empty() && line[0] == '/') {
            p.whole_path = true;
            line.remove_prefix(1);
        }
        if (line.empty()) {
            continue;
        }
        p.whole_path = p.whole_path || line.find('/') != std::string_view::npos;
        p.glob = std::string(line);
        patterns_.push_back(std::move(p));
    }
}

IgnoreList IgnoreList::load(const fs::path& file) {
    std::error_code ec;
    if (!fs::exists(file, ec)) {
        return {};
    }
    std::ifstream in(file, std::ios::binary);
    if (!in) {
        throw fs::filesystem_error("cannot read ignore file", file,
                                   std::make_error_code(std::errc::permission_denied));
    }
    std::ostringstream text;
    text << in.rdbuf();
    return IgnoreList(text.str());
}

bool IgnoreList::ignores(std::string_view path, bool is_directory) const {
    const auto slash = path.rfind('/');
    const auto name = slash == std::string_view::npos ? path : path.substr(slash + 1);

    for (const auto& p : patterns_) {
        if (p.folders_only && !is_directory) {
            continue;
        }
        if (glob_match(p.glob, p.whole_path ? path : name)) {
            return true;
        }
    }
    return false;
}

}  // namespace unsecret
