#pragma once

#include <memory>
#include <string_view>
#include <vector>

#include "unsecret/rule.hpp"

namespace unsecret {

std::vector<std::unique_ptr<Rule>> default_rules();

// Values like ${DB_PASS}, <password>, changeme or xxxxxxxx.
bool looks_like_placeholder(std::string_view value);

}  // namespace unsecret
