#pragma once

#include <filesystem>
#include <string>

namespace unsecret {

// A path as UTF-8 with "/" between parts. On MSVC, generic_string() throws for
// names outside the ANSI code page.
inline std::string path_text(const std::filesystem::path& path) {
    const auto text = path.generic_u8string();
    return std::string(text.begin(), text.end());
}

}  // namespace unsecret
