#pragma once

#include <cstddef>
#include <string_view>

#include "unsecret/rule.hpp"

namespace unsecret {

// Bits per character.
double shannon_entropy(std::string_view s);

// Only 0-9, a-f, A-F.
bool is_hex(std::string_view s);

// 8-4-4-4-12 hex digits.
bool is_uuid(std::string_view s);

// Flags long, random-looking words. Hex words get their own threshold:
// with 16 letters they can never pass 4 bits.
class EntropyRule : public Rule {
public:
    // Start values, to be tuned on real repos.
    static constexpr double default_hex_threshold = 3.0;
    static constexpr double default_base64_threshold = 4.5;
    static constexpr std::size_t default_min_length = 20;

    EntropyRule(double hex_threshold = default_hex_threshold,
                double base64_threshold = default_base64_threshold,
                std::size_t min_length = default_min_length, bool uuid_as_hex = true);

    std::string_view id() const override;
    std::vector<Match> find(std::string_view line) const override;
    bool is_fallback() const override { return true; }

private:
    double hex_threshold_;
    double base64_threshold_;
    std::size_t min_length_;
    bool uuid_as_hex_;
};

}  // namespace unsecret
