#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace unsecret {

// Finds many keywords in one pass (Aho-Corasick). Ignores ASCII case.
class KeywordFilter {
public:
    static constexpr std::size_t max_groups = 64;

    KeywordFilter() = default;
    // Each keyword belongs to a group (0 to 63).
    explicit KeywordFilter(const std::vector<std::pair<std::string, std::size_t>>& keywords);

    // Bit i is set if a keyword of group i is in `text`.
    std::uint64_t find(std::string_view text) const;

private:
    struct State {
        std::array<std::uint32_t, 256> next{};
        std::uint64_t groups = 0;
    };
    std::vector<State> states_;
};

}  // namespace unsecret
