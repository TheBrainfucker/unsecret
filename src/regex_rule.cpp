#include "unsecret/regex_rule.hpp"

#include <utility>

namespace unsecret {

RegexRule::RegexRule(std::string id, const std::string& pattern)
    : id_(std::move(id)), pattern_(pattern) {}

std::string_view RegexRule::id() const { return id_; }

std::vector<std::string> RegexRule::find(std::string_view line) const {
    // TODO (Milestone 2): iterate over all regex matches in `line`
    // (hint: std::regex_iterator) and collect each match as a string.
    (void)line;
    return {};
}

}  // namespace unsecret
