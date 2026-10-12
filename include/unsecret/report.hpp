#pragma once

#include <ostream>
#include <string>
#include <string_view>

#include "unsecret/scanner.hpp"

namespace unsecret {

// Shows the first 4 characters only if 16 or longer. Never shows the length.
std::string mask(std::string_view secret);

// One line per finding to `out`; warnings and the summary to `summary`.
void print_report(const ScanResult& result, std::ostream& out, std::ostream& summary);

}  // namespace unsecret
