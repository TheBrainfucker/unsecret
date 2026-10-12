#include "unsecret/entropy_rule.hpp"

#include <array>
#include <cmath>

namespace unsecret {

namespace {

bool is_hex(char c) {
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

EntropyRule::EntropyRule(double hex_threshold, double base64_threshold, std::size_t min_length)
    : hex_threshold_(hex_threshold), base64_threshold_(base64_threshold), min_length_(min_length) {}

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
        bool hex = true;
        while (i < line.size() && is_word_char(line[i])) {
            hex = hex && is_hex(line[i]);
            ++i;
        }
        const auto word = line.substr(start, i - start);
        if (word.size() >= min_length_ &&
            shannon_entropy(word) >= (hex ? hex_threshold_ : base64_threshold_)) {
            matches.push_back({start, word.size()});
        }
    }
    return matches;
}

}  // namespace unsecret
