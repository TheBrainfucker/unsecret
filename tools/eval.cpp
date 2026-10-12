// Helps label findings and tune the entropy thresholds.
//   unsecret_eval scan <out.tsv> [--unmasked] <folder>...
//   unsecret_eval score <labeled.tsv>
//   unsecret_eval credata <out.tsv> <credata-meta-folder> [--half tune|test]
// Label: put tp (real or test secret) or fp in the first column.

#include <cstdio>
#include <exception>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <memory>
#include <sstream>
#include <stdexcept>
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
        std::printf("%s: %zu findings in %zu files (skipped %zu binary, %zu too large, "
                    "%zu unreadable)\n",
                    folder.c_str(), result.findings.size(), result.files_scanned,
                    result.skipped_binary, result.skipped_large, result.unreadable.size());
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
    std::string location;  // path:line:column
};

std::vector<Row> read_rows(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("cannot read " + path);
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
        if (cols.size() < 6) {
            continue;
        }
        rows.push_back({cols[0], cols[1], std::stod(cols[2]), cols[3] == "hex", cols[5]});
    }
    return rows;
}

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
    const auto rows = read_rows(path);

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

// CredData labels: https://github.com/Samsung/CredData
// A label covers lines first..last of a file. T is a real secret; F and X are not.
struct Label {
    std::size_t first = 0;
    std::size_t last = 0;
    bool truth = false;
    std::string category;
    std::size_t id = 0;  // index into the found flags
};

std::vector<std::string> split_csv(const std::string& line) {
    std::vector<std::string> cols(1);
    bool quoted = false;
    for (const char c : line) {
        if (c == '"') {
            quoted = !quoted;
        } else if (c == ',' && !quoted) {
            cols.emplace_back();
        } else if (c != '\r') {
            cols.back() += c;
        }
    }
    return cols;
}

// CredData paths look like data/<repo id>/...
std::string_view repo_of(std::string_view path) {
    const auto first = path.find('/');
    if (first == std::string_view::npos) {
        return {};
    }
    const auto second = path.find('/', first + 1);
    return path.substr(first + 1, second == std::string_view::npos ? second : second - first - 1);
}

// Repo IDs are hex hashes, so this splits the repos about in half:
// tune with 0-7, report with 8-f.
bool in_half(std::string_view path, std::string_view half) {
    if (half == "all") {
        return true;
    }
    const auto repo = repo_of(path);
    if (repo.empty()) {
        return false;
    }
    const bool tune = repo[0] >= '0' && repo[0] <= '7';
    return half == "tune" ? tune : !tune;
}

struct Labels {
    std::map<std::string, std::vector<Label>> by_file;
    std::vector<std::pair<std::string, std::size_t>> truths;  // category, id
    std::size_t count = 0;
};

Labels read_labels(const std::filesystem::path& meta, std::string_view half) {
    Labels labels;
    for (const auto& entry : std::filesystem::directory_iterator(meta)) {
        if (entry.path().extension() != ".csv") {
            continue;
        }
        std::ifstream in(entry.path(), std::ios::binary);
        std::string line;
        std::getline(in, line);
        const auto header = split_csv(line);
        auto column = [&](std::string_view name) {
            for (std::size_t i = 0; i < header.size(); ++i) {
                if (header[i] == name) {
                    return i;
                }
            }
            throw std::runtime_error("no column " + std::string(name) + " in " +
                                     entry.path().string());
        };
        const auto path_col = column("FilePath");
        const auto first_col = column("LineStart");
        const auto last_col = column("LineEnd");
        const auto truth_col = column("GroundTruth");
        const auto category_col = column("Category");

        while (std::getline(in, line)) {
            const auto cols = split_csv(line);
            if (cols.size() < header.size() || !in_half(cols[path_col], half)) {
                continue;
            }
            Label label;
            label.first = std::stoul(cols[first_col]);
            label.last = std::stoul(cols[last_col]);
            label.truth = cols[truth_col] == "T";
            label.category = cols[category_col];
            label.id = labels.count++;
            labels.by_file[cols[path_col]].push_back(label);
        }
    }
    for (const auto& [file, list] : labels.by_file) {
        for (const auto& label : list) {
            if (label.truth) {
                labels.truths.emplace_back(label.category, label.id);
            }
        }
    }
    return labels;
}

struct Outcome {
    Counts counts;  // tp: on a T line, fp: on an F or X line
    std::vector<bool> found;
    std::size_t truths_found = 0;
};

// Counts all regex hits, plus entropy hits at or above the thresholds.
Outcome judge(const std::vector<Row>& rows, const Labels& labels, bool entropy, double hex_t,
              double other_t) {
    Outcome out;
    out.found.assign(labels.count, false);
    for (const auto& r : rows) {
        if (r.rule == entropy_id && (!entropy || r.entropy < (r.hex ? hex_t : other_t))) {
            continue;
        }
        const auto col_colon = r.location.rfind(':');
        const auto line_colon = r.location.rfind(':', col_colon - 1);
        const auto file = r.location.substr(0, line_colon);
        const auto line = std::stoul(r.location.substr(line_colon + 1, col_colon - line_colon - 1));

        bool on_truth = false;
        bool on_false = false;
        if (const auto it = labels.by_file.find(file); it != labels.by_file.end()) {
            for (const auto& label : it->second) {
                if (line < label.first || line > label.last) {
                    continue;
                }
                (label.truth ? on_truth : on_false) = true;
                if (label.truth && !out.found[label.id]) {
                    out.found[label.id] = true;
                    ++out.truths_found;
                }
            }
        }
        out.counts.add(on_truth ? "tp" : on_false ? "fp" : "");
    }
    return out;
}

double percent(std::size_t part, std::size_t whole) {
    return whole ? 100.0 * static_cast<double>(part) / static_cast<double>(whole) : 0.0;
}

void print_outcome(const std::string& name, const Outcome& o, std::size_t truths) {
    const auto& c = o.counts;
    std::printf("%-30s %7.1f%% %9.1f%% %9.1f%% %8zu %7zu %7zu %9zu\n", name.c_str(),
                percent(o.truths_found, truths), percent(c.tp, c.tp + c.fp),
                percent(c.tp, c.total()), c.total(), c.tp, c.fp, c.unlabeled);
}

void print_outcome_header(const char* first) {
    std::printf("%-30s %8s %10s %10s %8s %7s %7s %9s\n", first, "recall", "prec(lab)",
                "prec(all)", "found", "true", "false", "unlabeled");
}

int credata(const std::string& tsv, const std::string& meta, const std::string& half) {
    auto rows = read_rows(tsv);
    std::erase_if(rows, [&](const Row& r) { return !in_half(r.location, half); });
    const auto labels = read_labels(meta, half);
    const auto truths = labels.truths.size();

    std::set<std::string_view> repos;
    for (const auto& [file, list] : labels.by_file) {
        repos.insert(repo_of(file));
    }
    std::printf("half: %s (tune: repo IDs 0-7, test: 8-f)\n", half.c_str());
    std::printf("labels: %zu true (T), %zu false (F, X), in %zu files of %zu repos\n", truths,
                labels.count - truths, labels.by_file.size(), repos.size());
    std::printf("findings: %zu rows\n", rows.size());
    std::printf("recall: share of T labels hit. prec(lab): true / (true + false).\n"
                "prec(all): the same, with unlabeled lines counted as false.\n\n");

    const double hex_default = unsecret::EntropyRule::default_hex_threshold;
    const double other_default = unsecret::EntropyRule::default_base64_threshold;

    print_outcome_header("rule (entropy at default)");
    std::map<std::string, std::vector<Row>> by_rule;
    for (const auto& r : rows) {
        by_rule[r.rule].push_back(r);
    }
    for (const auto& [rule, rule_rows] : by_rule) {
        print_outcome(rule, judge(rule_rows, labels, true, hex_default, other_default), truths);
    }

    std::printf("\n");
    print_outcome_header("whole tool, entropy hex/other");
    print_outcome("no entropy rule", judge(rows, labels, false, 0, 0), truths);
    for (const auto& [hex_t, other_t] : threshold_pairs) {
        char name[48];
        std::snprintf(name, sizeof name, "%.2f / %.2f", hex_t, other_t);
        print_outcome(name, judge(rows, labels, true, hex_t, other_t), truths);
    }
    std::printf("\n");
    print_outcome_header("whole tool, one threshold");
    for (const auto t : single_thresholds) {
        char name[48];
        std::snprintf(name, sizeof name, "%.2f", t);
        print_outcome(name, judge(rows, labels, true, t, t), truths);
    }

    const auto chosen = judge(rows, labels, true, hex_default, other_default);
    std::map<std::string, std::pair<std::size_t, std::size_t>> by_category;  // found, total
    for (const auto& [category, id] : labels.truths) {
        auto& [found, total] = by_category[category];
        ++total;
        found += chosen.found[id] ? 1 : 0;
    }
    std::printf("\nrecall by CredData category (entropy at default)\n");
    std::printf("%-40s %7s %7s %8s\n", "category", "true", "found", "recall");
    for (const auto& [category, counts] : by_category) {
        std::printf("%-40s %7zu %7zu %7.1f%%\n", category.c_str(), counts.second, counts.first,
                    percent(counts.first, counts.second));
    }
    return 0;
}

int usage() {
    std::fprintf(stderr,
                 "usage: unsecret_eval scan <out.tsv> [--unmasked] <folder>...\n"
                 "       unsecret_eval score <labeled.tsv>\n"
                 "       unsecret_eval credata <out.tsv> <credata-meta-folder> [--half tune|test]\n");
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
        if (args.size() == 3 && args[0] == "credata") {
            return credata(args[1], args[2], "all");
        }
        if (args.size() == 5 && args[0] == "credata" && args[3] == "--half" &&
            (args[4] == "tune" || args[4] == "test")) {
            return credata(args[1], args[2], args[4]);
        }
        return usage();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "unsecret_eval: %s\n", e.what());
        return 2;
    }
}
