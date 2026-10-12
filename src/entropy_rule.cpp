#include "unsecret/entropy_rule.hpp"

namespace unsecret {

double shannon_entropy(std::string_view s) {
    // TODO (Milestone 3): count how often each byte occurs,
    // then compute  -sum(p * log2(p))  over all byte frequencies p.
    (void)s;
    return 0.0;
}

EntropyRule::EntropyRule(double threshold, std::size_t min_length)
    : threshold_(threshold), min_length_(min_length) {}

std::string_view EntropyRule::id() const { return "high-entropy-string"; }

std::vector<Match> EntropyRule::find(std::string_view line) const {
    // TODO (Milestone 3): split `line` into tokens (decide what counts as a
    // separator: spaces, quotes, '=', ':' ...), and return tokens that are at
    // least min_length_ long with entropy >= threshold_, as positions in `line`.
    (void)line;
    return {};
}

}  // namespace unsecret
