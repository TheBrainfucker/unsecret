#pragma once

#include <regex>
#include <string>

#include "unsecret/rule.hpp"

namespace unsecret {

// If the pattern has a group, only group 1 is reported.
// Keep repeats bounded ({8,128}, not +): std::regex is recursive.
class RegexRule : public Rule {
public:
    RegexRule(std::string id, const std::string& pattern,
              std::regex::flag_type flags = std::regex::ECMAScript);

    std::string_view id() const override;
    std::vector<Match> find(std::string_view line) const override;

private:
    std::string id_;
    std::regex pattern_;
};

}  // namespace unsecret
