#include "unsecret/regex_rule.hpp"

#include <utility>

namespace unsecret {

RegexRule::RegexRule(std::string id, const std::string& pattern, std::vector<std::string> keywords,
                     std::regex::flag_type flags)
    : id_(std::move(id)), pattern_(pattern, flags), keywords_(std::move(keywords)) {}

std::string_view RegexRule::id() const { return id_; }

std::vector<std::string> RegexRule::keywords() const { return keywords_; }

std::vector<Match> RegexRule::find(std::string_view line) const {
    using Iterator = std::regex_iterator<std::string_view::const_iterator>;
    const int group = pattern_.mark_count() > 0 ? 1 : 0;

    std::vector<Match> matches;
    for (Iterator it(line.begin(), line.end(), pattern_), end; it != end; ++it) {
        const auto& m = *it;
        if (m[group].matched && m.length(group) > 0) {
            matches.push_back({static_cast<std::size_t>(m.position(group)),
                               static_cast<std::size_t>(m.length(group))});
        }
    }
    return matches;
}

}  // namespace unsecret
