// Scan speed with and without the prefilter.
// Usage: unsecret_bench [folder]   (no folder: a made-up 4 MB corpus)

#include <chrono>
#include <cstdio>
#include <exception>
#include <random>
#include <string>
#include <string_view>
#include <vector>

#include "unsecret/default_rules.hpp"
#include "unsecret/scanner.hpp"

namespace {

// Code-like lines. About 1 in 100 has a keyword, 1 in 5000 a fake key.
std::string make_corpus(std::size_t bytes) {
    const std::vector<std::string_view> words = {
        "int", "const", "auto", "return", "if", "else", "for", "while", "std::string",
        "value", "count", "result", "name", "path", "config", "user", "index", "buffer",
        "=", "==", "(", ")", "{", "}", ";", ",", "+", "->", "0", "1", "42", "\"hello\"",
        "// note", "#include", "<vector>", "size()", "push_back(x)", "nullptr", "true"};
    const std::vector<std::string_view> keyword_words = {"token", "api", "secret", "password"};
    const std::string fake_key = std::string("AKIA") + "IOSFODNN7EXAMPLE";

    std::mt19937 random(42);
    std::uniform_int_distribution<std::size_t> pick(0, words.size() - 1);
    std::uniform_int_distribution<std::size_t> pick_keyword(0, keyword_words.size() - 1);
    std::uniform_int_distribution<int> length(3, 12);
    std::uniform_int_distribution<int> chance(0, 9999);

    std::string text;
    text.reserve(bytes + 256);
    while (text.size() < bytes) {
        text += "    ";
        for (int n = length(random); n > 0; --n) {
            text += words[pick(random)];
            text += ' ';
        }
        const int roll = chance(random);
        if (roll < 100) {
            text += keyword_words[pick_keyword(random)];
        }
        if (roll < 2) {
            text += " = \"" + fake_key + "\"";
        }
        text += '\n';
    }
    return text;
}

unsecret::Scanner make_scanner(bool prefilter) {
    unsecret::Scanner scanner;
    for (auto& rule : unsecret::default_rules()) {
        scanner.add_rule(std::move(rule));
    }
    scanner.use_prefilter(prefilter);
    return scanner;
}

struct Run {
    double seconds = 0;
    std::uintmax_t bytes = 0;
    std::size_t findings = 0;
};

// Best of 3, to hide noise.
template <typename Scan>
Run best_of_3(Scan scan) {
    Run best;
    for (int i = 0; i < 3; ++i) {
        const auto start = std::chrono::steady_clock::now();
        Run run = scan();
        run.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
        if (i == 0 || run.seconds < best.seconds) {
            best = run;
        }
    }
    return best;
}

void print(const char* label, const Run& run) {
    std::printf("%-15s %8.1f MB/s   %zu findings\n", label,
                static_cast<double>(run.bytes) / (1024.0 * 1024.0) / run.seconds, run.findings);
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc > 2) {
        std::fprintf(stderr, "usage: unsecret_bench [folder]\n");
        return 2;
    }
    try {
        Run runs[2];
        for (const bool prefilter : {false, true}) {
            const auto scanner = make_scanner(prefilter);
            if (argc == 2) {
                runs[prefilter] = best_of_3([&] {
                    const auto result = scanner.scan(argv[1]);
                    return Run{0, result.bytes_scanned, result.findings.size()};
                });
            } else {
                static const auto corpus = make_corpus(4 * 1024 * 1024);
                runs[prefilter] = best_of_3([&] {
                    std::vector<unsecret::Finding> findings;
                    scanner.scan_text(corpus, "corpus", findings);
                    return Run{0, corpus.size(), findings.size()};
                });
            }
        }

        std::printf("input: %s\n", argc == 2 ? argv[1] : "made-up corpus");
        print("prefilter off:", runs[0]);
        print("prefilter on:", runs[1]);
        std::printf("speedup: %.1fx\n", runs[0].seconds / runs[1].seconds);
        if (runs[0].findings != runs[1].findings) {
            std::fprintf(stderr, "error: findings differ\n");
            return 1;
        }
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "unsecret_bench: %s\n", e.what());
        return 2;
    }
}
