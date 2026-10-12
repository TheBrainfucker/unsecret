// Helps label findings and tune the entropy thresholds.
//   unsecret_eval scan <out.tsv> [--unmasked] <folder>...
//   unsecret_eval score <labeled.tsv>
// Label: put tp (real or test secret) or fp in the first column.

#include <cstdio>
#include <exception>
#include <fstream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "unsecret/default_rules.hpp"
#include "unsecret/entropy_rule.hpp"
#include "unsecret/report.hpp"
#include "unsecret/scanner.hpp"

namespace {

constexpr std::string_view entropy_id = "high-entropy-string";

// Low, so every threshold below can be tried later.
constexpr double lowest_hex = 3.0;
constexpr double lowest_other = 4.0;

const std::vector<std::pair<double, double>> threshold_pairs = {
    {3.0, 4.0}, {3.0, 4.25}, {3.0, 4.5}, {3.25, 4.5}, {3.5, 4.5},
    {3.0, 4.75}, {3.5, 4.75}, {3.5, 5.0}};
const std::vector<double> single_thresholds = {4.0, 4.25, 4.5};

std::string no_tabs(std::string s) {
    for (auto& c : s) {
        if (c == '\t' || c == '\n' || c == '\r') {
            c = ' ';
        }
    }
    return s;
}

int scan(const std::string& out_path, bool unmasked, const std::vector<std::string>& folders) {
    unsecret::Scanner scanner;
    for (auto& rule : unsecret::default_rules()) {
        if (rule->id() != entropy_id) {
            scanner.add_rule(std::move(rule));
        }
    }
    scanner.add_rule(std::make_unique<unsecret::EntropyRule>(lowest_hex, lowest_other));

    std::ofstream out(out_path, std::ios::binary);
    if (!out) {
        std::fprintf(stderr, "cannot write %s\n", out_path.c_str());
        return 2;
    }
    out << "label\trule\tentropy\tcharset\tlength\tlocation\tvalue\n";

    std::size_t total = 0;
    for (const auto& folder : folders) {
        const auto result = scanner.scan(folder);
        for (const auto& f : result.findings) {
            char entropy[16];
            std::snprintf(entropy, sizeof entropy, "%.3f", unsecret::shannon_entropy(f.match));
            out << '\t' << f.rule_id << '\t' << entropy << '\t'
                << (unsecret::is_hex(f.match) ? "hex" : "other") << '\t' << f.match.size() << '\t'
                << folder << '/' << f.file.generic_string() << ':' << f.line << ':' << f.column
                << '\t' << no_tabs(unmasked ? f.match : unsecret::mask(f.match)) << '\n';
        }
        total += result.findings.size();
        std::printf("%s: %zu findings, %zu files\n", folder.c_str(), result.findings.size(),
                    result.files_scanned);
    }
    std::printf("wrote %zu rows to %s\n", total, out_path.c_str());
    if (unmasked) {
        std::printf("warning: real values are in the file. Keep it out of git.\n");
    }
    return 0;
}

struct Row {
    std::string label;
    std::string rule;
    double entropy = 0;
    bool hex = false;
};

struct Counts {
    std::size_t tp = 0, fp = 0, unlabeled = 0;
    void add(const std::string& label) {
        if (label == "tp") {
            ++tp;
        } else if (label == "fp") {
            ++fp;
        } else {
            ++unlabeled;
        }
    }
    std::size_t total() const { return tp + fp + unlabeled; }
};

void print_counts(const std::string& name, const Counts& c) {
    std::printf("%-34s %6zu %6zu %6zu %10zu\n", name.c_str(), c.total(), c.tp, c.fp, c.unlabeled);
}

int score(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::fprintf(stderr, "cannot read %s\n", path.c_str());
        return 2;
    }
    std::vector<Row> rows;
    std::string line;
    std::getline(in, line);  // header
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        std::vector<std::string> cols;
        std::stringstream fields(line);
        for (std::string col; std::getline(fields, col, '\t');) {
            cols.push_back(col);
        }
        if (cols.size() < 4) {
            continue;
        }
        rows.push_back({cols[0], cols[1], std::stod(cols[2]), cols[3] == "hex"});
    }

    std::printf("%-34s %6s %6s %6s %10s\n", "rule", "found", "tp", "fp", "unlabeled");
    std::map<std::string, Counts> by_rule;
    for (const auto& r : rows) {
        if (r.rule != entropy_id) {
            by_rule[r.rule].add(r.label);
        }
    }
    for (const auto& [rule, counts] : by_rule) {
        print_counts(rule, counts);
    }

    auto entropy_counts = [&](double hex_t, double other_t) {
        Counts c;
        for (const auto& r : rows) {
            if (r.rule == entropy_id && r.entropy >= (r.hex ? hex_t : other_t)) {
                c.add(r.label);
            }
        }
        return c;
    };
    std::printf("\nentropy, two thresholds (hex / other)\n");
    for (const auto& [hex_t, other_t] : threshold_pairs) {
        char name[48];
        std::snprintf(name, sizeof name, "%.2f / %.2f", hex_t, other_t);
        print_counts(name, entropy_counts(hex_t, other_t));
    }
    std::printf("\nentropy, one threshold for both\n");
    for (const auto t : single_thresholds) {
        char name[48];
        std::snprintf(name, sizeof name, "%.2f", t);
        print_counts(name, entropy_counts(t, t));
    }
    return 0;
}

int usage() {
    std::fprintf(stderr,
                 "usage: unsecret_eval scan <out.tsv> [--unmasked] <folder>...\n"
                 "       unsecret_eval score <labeled.tsv>\n");
    return 2;
}

}  // namespace

int main(int argc, char* argv[]) {
    const std::vector<std::string> args(argv + 1, argv + argc);
    try {
        if (args.size() >= 3 && args[0] == "scan") {
            bool unmasked = false;
            std::vector<std::string> folders;
            for (std::size_t i = 2; i < args.size(); ++i) {
                if (args[i] == "--unmasked") {
                    unmasked = true;
                } else {
                    folders.push_back(args[i]);
                }
            }
            return folders.empty() ? usage() : scan(args[1], unmasked, folders);
        }
        if (args.size() == 2 && args[0] == "score") {
            return score(args[1]);
        }
        return usage();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "unsecret_eval: %s\n", e.what());
        return 2;
    }
}
