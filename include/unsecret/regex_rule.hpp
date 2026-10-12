#pragma once

#include <regex>
#include <string>

#include "unsecret/rule.hpp"

namespace unsecret {

// Detects secrets with a known format (AWS keys, GitHub tokens, private key headers...).
class RegexRule : public Rule {
public:
    RegexRule(std::string id, const std::string& pattern);

    std::string_view id() const override;
    std::vector<Match> find(std::string_view line) const override;

private:
    std::string id_;
    std::regex pattern_;
};

}  // namespace unsecret
