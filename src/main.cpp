#include <exception>
#include <iostream>
#include <memory>

#include "unsecret/entropy_rule.hpp"
#include "unsecret/regex_rule.hpp"
#include "unsecret/scanner.hpp"

// Exit codes: 0 = clean, 1 = secrets found, 2 = usage or runtime error.
// Exit code 1 is what lets a git hook or CI job block the commit.
int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "usage: unsecret <file-or-directory>\n";
        return 2;
    }

    try {
        // Rules are registered inside the try: RegexRule compiles its pattern in the
        // constructor, and an invalid pattern throws std::regex_error.
        unsecret::Scanner scanner;

        // TODO (Milestone 2): register your RegexRules here. Check every pattern
        // against the vendor's own documentation before adding it.
        // scanner.add_rule(std::make_unique<unsecret::RegexRule>("rule-id", "pattern"));

        // TODO (Milestone 3): register an EntropyRule and tune its threshold.

        const auto findings = scanner.scan(argv[1]);

        // TODO (Milestone 4): print each finding as file:line [rule-id] masked-match.
        // Never print the full secret.

        return findings.empty() ? 0 : 1;
    } catch (const std::exception& e) {
        std::cerr << "unsecret: " << e.what() << '\n';
        return 2;
    }
}
