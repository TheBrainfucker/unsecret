#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace unsecret {

// Base class for every detection rule.
// A rule looks at one line of text and returns the suspicious substrings it found.
class Rule {
public:
    virtual ~Rule() = default;

    // Stable identifier shown in output, e.g. "aws-access-key-id".
    virtual std::string_view id() const = 0;

    // Return every match in this line (empty vector = nothing found).
    virtual std::vector<std::string> find(std::string_view line) const = 0;
};

}  // namespace unsecret
