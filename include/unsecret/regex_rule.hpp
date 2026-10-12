#pragma once

#include <functional>
#include <regex>
#include <string>
#include <string_view>
#include <vector>

#include "unsecret/rule.hpp"

namespace unsecret {

struct RegexOptions {
    std::vector<std::string> keywords{};
    std::regex::flag_type flags = std::regex::ECMAScript;
    std::function<bool(std::string_view)> keep{};  // a hit is dropped if this says false
};

// If the pattern has a group, only group 1 is reported.
// Keep repeats bounded ({8,128}, not +): std::regex is recursive.
class RegexRule : public Rule {
public:
    RegexRule(std::string id, const std::string& pattern, RegexOptions options = {});

    std::string_view id() const override;
    std::vector<Match> find(std::string_view line) const override;
    std::vector<std::string> keywords() const override;

private:
    std::string id_;
    std::regex pattern_;
    RegexOptions options_;
};

}  // namespace unsecret
