#include <catch2/catch_test_macros.hpp>

#include <sstream>
#include <string>

#include "unsecret/report.hpp"

using unsecret::mask;

TEST_CASE("mask hides short secrets fully and keeps 4 characters of long ones") {
    CHECK(mask("") == "********");
    CHECK(mask("hunter2hunter2") == "********");             // 14: all hidden
    CHECK(mask("abcdefghijklmnop") == "abcd********");        // 16: prefix shown
    CHECK(mask(std::string(2000, 'x')) == "xxxx********");   // length not shown
}

TEST_CASE("report prints masked findings and a summary") {
    unsecret::ScanResult result;
    result.findings.push_back({"sub/config.py", 2, 12, "aws-access-key-id", "AKIA" + std::string(16, 'Q')});
    result.findings.push_back({"sub/config.py", 5, 1, "generic-password-assignment", "letmein!"});
    result.files_scanned = 3;
    result.bytes_scanned = 2048;
    result.skipped_binary = 1;
    result.unreadable.push_back("locked.txt");

    std::ostringstream out;
    std::ostringstream summary;
    unsecret::print_report(result, out, summary);

    CHECK(out.str() ==
          "sub/config.py:2:12 [aws-access-key-id] AKIA********\n"
          "sub/config.py:5:1 [generic-password-assignment] ********\n");
    CHECK(summary.str() ==
          "warning: could not read locked.txt\n"
          "2 findings in 1 file (scanned 3 files, 2.0 KB; skipped 1 binary, 1 unreadable)\n");
}

TEST_CASE("report on a clean scan") {
    unsecret::ScanResult result;
    result.files_scanned = 1;
    result.bytes_scanned = 10;

    std::ostringstream out;
    std::ostringstream summary;
    unsecret::print_report(result, out, summary);

    CHECK(out.str().empty());
    CHECK(summary.str() == "no findings (scanned 1 file, 10 bytes)\n");
}
