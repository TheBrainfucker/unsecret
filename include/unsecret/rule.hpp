#pragma once

#include <cstddef>
#include <string_view>
#include <vector>

namespace unsecret {

// A hit at line.substr(pos, len).
struct Match {
    std::size_t pos = 0;
    std::size_t len = 0;
};

class Rule {
public:
    virtual ~Rule() = default;

    // Shown in output, e.g. "aws-access-key-id".
    virtual std::string_view id() const = 0;

    virtual std::vector<Match> find(std::string_view line) const = 0;
};

}  // namespace unsecret
