#include "unsecret/entropy_rule.hpp"

namespace unsecret {

double shannon_entropy(std::string_view s) {
    // TODO: -sum(p * log2(p)) over byte frequencies.
    (void)s;
    return 0.0;
}

EntropyRule::EntropyRule(double threshold, std::size_t min_length)
    : threshold_(threshold), min_length_(min_length) {}

std::string_view EntropyRule::id() const { return "high-entropy-string"; }

std::vector<Match> EntropyRule::find(std::string_view line) const {
    // TODO: split into words; return long ones with high entropy.
    (void)line;
    return {};
}

}  // namespace unsecret
