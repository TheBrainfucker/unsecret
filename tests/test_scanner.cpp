#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <random>
#include <string>
#include <string_view>
#include <vector>

#include "unsecret/scanner.hpp"

namespace fs = std::filesystem;
using namespace std::string_literals;

namespace {

class MarkerRule : public unsecret::Rule {
public:
    std::string_view id() const override { return "marker"; }
    std::vector<unsecret::Match> find(std::string_view line) const override {
        std::vector<unsecret::Match> out;
        for (auto pos = line.find(marker); pos != std::string_view::npos;
             pos = line.find(marker, pos + marker.size())) {
            out.push_back({pos, marker.size()});
        }
        return out;
    }

private:
    static constexpr std::string_view marker = "FINDME";
};

// Shows exactly what the scanner passes in.
class WholeLineRule : public unsecret::Rule {
public:
    std::string_view id() const override { return "line"; }
    std::vector<unsecret::Match> find(std::string_view line) const override {
        if (line.empty()) {
            return {};
        }
        return {{0, line.size()}};
    }
};

// Built at runtime, so no .git folder or binary file lives in the repo.
class TempDir {
public:
    TempDir() {
        std::random_device rd;
        const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        path_ = fs::temp_directory_path() /
                ("unsecret-test-" + std::to_string(stamp) + "-" + std::to_string(rd()));
        fs::create_directories(path_);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path_, ec);
    }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;

    const fs::path& path() const { return path_; }

    void write(const fs::path& relative, std::string_view content) const {
        const auto file = path_ / relative;
        fs::create_directories(file.parent_path());
        std::ofstream out(file, std::ios::binary);
        out.write(content.data(), static_cast<std::streamsize>(content.size()));
    }

private:
    fs::path path_;
};

unsecret::Scanner marker_scanner(std::uintmax_t max_file_size = unsecret::Scanner::default_max_file_size) {
    unsecret::Scanner scanner(max_file_size);
    scanner.add_rule(std::make_unique<MarkerRule>());
    return scanner;
}

}  // namespace

TEST_CASE("binary detection looks for a NUL byte in the first 8 KB") {
    CHECK_FALSE(unsecret::looks_binary("plain text\n"));
    CHECK_FALSE(unsecret::looks_binary(""));
    CHECK(unsecret::looks_binary("PK\x03\x04\0\0"s));
    CHECK_FALSE(unsecret::looks_binary(std::string(8 * 1024, 'a') + '\0'));
}

TEST_CASE("scan_text reports 1-based line and column") {
    const auto scanner = marker_scanner();
    std::vector<unsecret::Finding> findings;
    scanner.scan_text("nothing\n  FINDME and FINDME\n", "f.txt", findings);

    REQUIRE(findings.size() == 2);
    CHECK(findings[0].file == "f.txt");
    CHECK(findings[0].line == 2);
    CHECK(findings[0].column == 3);
    CHECK(findings[0].rule_id == "marker");
    CHECK(findings[0].match == "FINDME");
    CHECK(findings[1].column == 14);
}

TEST_CASE("scan_text strips CRLF and a UTF-8 BOM, and reads a last line without newline") {
    unsecret::Scanner scanner;
    scanner.add_rule(std::make_unique<WholeLineRule>());
    std::vector<unsecret::Finding> findings;
    scanner.scan_text("\xEF\xBB\xBF" "first\r\nsecond\r\n\r\nlast", "f.txt", findings);

    REQUIRE(findings.size() == 3);
    CHECK(findings[0].match == "first");  // no BOM bytes, no '\r'
    CHECK(findings[1].match == "second");
    CHECK(findings[2].match == "last");
    CHECK(findings[2].line == 4);  // the empty line still counts
}

TEST_CASE("a fallback hit is dropped when it overlaps a normal hit") {
    class FallbackLineRule : public WholeLineRule {
    public:
        std::string_view id() const override { return "fallback"; }
        bool is_fallback() const override { return true; }
    };
    auto scanner = marker_scanner();
    scanner.add_rule(std::make_unique<FallbackLineRule>());

    std::vector<unsecret::Finding> findings;
    scanner.scan_text("x FINDME y\nplain\n", "f.txt", findings);

    REQUIRE(findings.size() == 2);
    CHECK(findings[0].rule_id == "marker");
    CHECK(findings[1].rule_id == "fallback");
    CHECK(findings[1].line == 2);
}

TEST_CASE("long lines are scanned in overlapping windows without duplicates or gaps") {
    using unsecret::Scanner;
    constexpr auto step = Scanner::window_size - Scanner::window_overlap;
    const auto scanner = marker_scanner();

    // Hits at the start, on both piece edges, and at the end.
    std::string line(3 * Scanner::window_size, '.');
    const std::vector<std::size_t> positions = {
        0, step - 3, Scanner::window_size - 3, line.size() - 6};
    for (const auto pos : positions) {
        line.replace(pos, 6, "FINDME");
    }

    std::vector<unsecret::Finding> findings;
    scanner.scan_text(line, "long.txt", findings);

    std::vector<std::size_t> columns;
    for (const auto& f : findings) {
        CHECK(f.match == "FINDME");
        columns.push_back(f.column - 1);
    }
    std::sort(columns.begin(), columns.end());
    CHECK(columns == positions);
}

TEST_CASE("scanning a directory visits text files and skips .git, binary and large files") {
    TempDir dir;
    dir.write("a.txt", "hello\nFINDME\n");
    dir.write("sub/deeper/b.txt", "x FINDME\r\n");
    dir.write(".git/config", "FINDME\n");
    dir.write("image.bin", "FINDME\0\x01\x02"s);
    dir.write("big.txt", std::string(200, 'a') + "\nFINDME\n");

    const auto result = marker_scanner(100).scan(dir.path());

    const auto& findings = result.findings;  // sorted by the scanner
    REQUIRE(findings.size() == 2);
    CHECK(findings[0].file.generic_string() == "a.txt");
    CHECK(findings[0].line == 2);
    CHECK(findings[1].file.generic_string() == "sub/deeper/b.txt");
    CHECK(findings[1].column == 3);

    CHECK(result.files_scanned == 2);
    CHECK(result.skipped_binary == 1);
    CHECK(result.skipped_large == 1);
    CHECK(result.unreadable.empty());
}

TEST_CASE("the folder's .unsecretignore skips files and whole folders") {
    TempDir dir;
    dir.write(".unsecretignore", "# fake keys\nfixtures/\n*.min.js\n");
    dir.write("fixtures/deep/key.txt", "FINDME");
    dir.write("web/app.min.js", "FINDME");
    dir.write("web/app.js", "FINDME");

    const auto result = marker_scanner().scan(dir.path());

    REQUIRE(result.findings.size() == 1);
    CHECK(result.findings[0].file.generic_string() == "web/app.js");
    CHECK(result.skipped_ignored == 2);  // the folder and the .min.js file
}

TEST_CASE("scanning a single file reports the path as given") {
    TempDir dir;
    dir.write("only.txt", "FINDME");

    const auto file = dir.path() / "only.txt";
    const auto result = marker_scanner().scan(file);

    REQUIRE(result.findings.size() == 1);
    CHECK(result.findings[0].file == file);
    CHECK(result.files_scanned == 1);
}

TEST_CASE("an empty directory is clean") {
    TempDir dir;
    const auto result = marker_scanner().scan(dir.path());
    CHECK(result.findings.empty());
    CHECK(result.files_scanned == 0);
}

TEST_CASE("a path that does not exist is an error") {
    TempDir dir;
    CHECK_THROWS_AS(marker_scanner().scan(dir.path() / "missing"), fs::filesystem_error);
}
