#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace unsecret {

// `*` any text but `/`, `**` any text, `?` one character but `/`.
bool glob_match(std::string_view pattern, std::string_view text);

// The .unsecretignore rules. A small part of .gitignore:
// "name/" is folders only, a pattern with no "/" matches at any depth, no "!".
class IgnoreList {
public:
    IgnoreList() = default;
    explicit IgnoreList(std::string_view text);

    // No file: empty list. A file that can't be read: throws.
    static IgnoreList load(const std::filesystem::path& file);

    // `path` is relative, with "/" between parts.
    bool ignores(std::string_view path, bool is_directory) const;

private:
    struct Pattern {
        std::string glob;
        bool folders_only = false;
        bool whole_path = false;
    };
    std::vector<Pattern> patterns_;
};

}  // namespace unsecret
