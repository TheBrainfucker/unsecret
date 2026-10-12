#pragma once

#include <cstddef>
#include <string_view>

#include "unsecret/rule.hpp"

namespace unsecret {

// Shannon entropy of a string, in bits per character.
double shannon_entropy(std::string_view s);

// Flags long, random-looking tokens that match no known format.
class EntropyRule : public Rule {
public:
    EntropyRule(double threshold, std::size_t min_length);

    std::string_view id() const override;
    std::vector<std::string> find(std::string_view line) const override;

private:
    double threshold_;
    std::size_t min_length_;
};

}  // namespace unsecret
