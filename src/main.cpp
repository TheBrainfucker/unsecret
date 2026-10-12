#include <exception>
#include <iostream>
#include <memory>
#include <utility>

#include "unsecret/default_rules.hpp"
#include "unsecret/entropy_rule.hpp"
#include "unsecret/report.hpp"
#include "unsecret/scanner.hpp"

// Exit codes: 0 clean, 1 secrets found, 2 error.
int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "usage: unsecret <file-or-directory>\n";
        return 2;
    }

    try {
        // A bad regex throws here, so this stays inside the try.
        unsecret::Scanner scanner;
        for (auto& rule : unsecret::default_rules()) {
            scanner.add_rule(std::move(rule));
        }

        // TODO: add the entropy rule.

        const auto result = scanner.scan(argv[1]);
        unsecret::print_report(result, std::cout, std::cerr);
        return result.findings.empty() ? 0 : 1;
    } catch (const std::exception& e) {
        std::cerr << "unsecret: " << e.what() << '\n';
        return 2;
    }
}
