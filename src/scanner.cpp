#include "unsecret/scanner.hpp"

#include <utility>

namespace unsecret {

void Scanner::add_rule(std::unique_ptr<Rule> rule) {
    rules_.push_back(std::move(rule));
}

std::vector<Finding> Scanner::scan(const std::filesystem::path& root) const {
    // TODO (Milestone 1): if `root` is a file, scan it directly.
    // If it is a directory, walk it with std::filesystem::recursive_directory_iterator,
    // skip things you should not scan (.git, binaries, very large files),
    // and call scan_file() on each regular file.
    (void)root;
    return {};
}

std::vector<Finding> Scanner::scan_file(const std::filesystem::path& file) const {
    // TODO (Milestone 1): open the file, read it line by line,
    // run every rule in rules_ on each line, and record a Finding per match.
    (void)file;
    return {};
}

bool Scanner::looks_binary(const std::filesystem::path& file) {
    // TODO (Milestone 1): read the first few KB and decide whether the file is
    // binary (a common heuristic: it contains a NUL byte).
    (void)file;
    return false;
}

}  // namespace unsecret
