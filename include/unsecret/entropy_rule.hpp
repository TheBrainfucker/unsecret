#pragma once

#include <cstddef>
#include <string_view>

#include "unsecret/rule.hpp"

namespace unsecret {

// Bits per character.
double shannon_entropy(std::string_view s);

// Flags long, random-looking words.
class EntropyRule : public Rule {
public:
    EntropyRule(double threshold, std::size_t min_length);

    std::string_view id() const override;
    std::vector<Match> find(std::string_view line) const override;

private:
    double threshold_;
    std::size_t min_length_;
};

}  // namespace unsecret
