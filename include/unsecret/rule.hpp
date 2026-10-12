#pragma once

#include <cstddef>
#include <string_view>
#include <vector>

namespace unsecret {

// Where a rule matched inside a line: the substring line.substr(pos, len).
// Positions (not copies) let the scanner drop overlapping findings and report a column.
struct Match {
    std::size_t pos = 0;  // 0-based offset into the line
    std::size_t len = 0;
};

// Base class for every detection rule.
// A rule looks at one line of text and returns where it found suspicious substrings.
class Rule {
public:
    virtual ~Rule() = default;

    // Stable identifier shown in output, e.g. "aws-access-key-id".
    virtual std::string_view id() const = 0;

    // Return every match in this line (empty vector = nothing found).
    virtual std::vector<Match> find(std::string_view line) const = 0;
};

}  // namespace unsecret
