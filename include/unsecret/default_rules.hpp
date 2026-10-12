#pragma once

#include <memory>
#include <vector>

#include "unsecret/rule.hpp"

namespace unsecret {

std::vector<std::unique_ptr<Rule>> default_rules();

}  // namespace unsecret
