#include "unsecret/entropy_rule.hpp"

#include <array>
#include <cmath>

namespace unsecret {

namespace {

bool is_hex_char(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

// Base64 and base64url letters, without the '=' padding.
bool is_word_char(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           c == '+' || c == '/' || c == '-' || c == '_';
}

}  // namespace

double shannon_entropy(std::string_view s) {
    if (s.empty()) {
        return 0.0;
    }
    std::array<std::size_t, 256> counts{};
    for (const char c : s) {
        ++counts[static_cast<unsigned char>(c)];
    }
    double bits = 0.0;
    for (const auto n : counts) {
        if (n > 0) {
            const double p = static_cast<double>(n) / static_cast<double>(s.size());
            bits -= p * std::log2(p);
        }
    }
    return bits;
}

bool is_hex(std::string_view s) {
    for (const char c : s) {
        if (!is_hex_char(c)) {
            return false;
        }
    }
    return true;
}

bool is_uuid(std::string_view s) {
    if (s.size() != 36) {
        return false;
    }
    for (std::size_t i = 0; i < s.size(); ++i) {
        const bool dash = i == 8 || i == 13 || i == 18 || i == 23;
        if (dash ? s[i] != '-' : !is_hex_char(s[i])) {
            return false;
        }
    }
    return true;
}

EntropyRule::EntropyRule(double hex_threshold, double base64_threshold, std::size_t min_length,
                         bool uuid_as_hex)
    : hex_threshold_(hex_threshold),
      base64_threshold_(base64_threshold),
      min_length_(min_length),
      uuid_as_hex_(uuid_as_hex) {}

std::string_view EntropyRule::id() const { return "high-entropy-string"; }

std::vector<Match> EntropyRule::find(std::string_view line) const {
    std::vector<Match> matches;
    std::size_t i = 0;
    while (i < line.size()) {
        if (!is_word_char(line[i])) {
            ++i;
            continue;
        }
        const std::size_t start = i;
        while (i < line.size() && is_word_char(line[i])) {
            ++i;
        }
        const auto word = line.substr(start, i - start);
        const bool hex = is_hex(word) || (uuid_as_hex_ && is_uuid(word));
        if (word.size() >= min_length_ &&
            shannon_entropy(word) >= (hex ? hex_threshold_ : base64_threshold_)) {
            matches.push_back({start, word.size()});
        }
    }
    return matches;
}

}  // namespace unsecret
