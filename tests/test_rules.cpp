#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_floating_point.hpp>

#include "unsecret/entropy_rule.hpp"
#include "unsecret/regex_rule.hpp"

using Catch::Matchers::WithinAbs;

// These tests describe the behaviour you are about to implement.
// Tests tagged [!shouldfail] are expected to fail until you fill in the TODOs.
// Once the feature works, such a test starts "failing" (it passed unexpectedly):
// that is the signal to delete its [!shouldfail] tag.

TEST_CASE("entropy of a single repeated character is zero") {
    REQUIRE_THAT(unsecret::shannon_entropy("aaaaaaaa"), WithinAbs(0.0, 1e-9));
}

TEST_CASE("entropy of two equally frequent characters is one bit", "[!shouldfail]") {
    REQUIRE_THAT(unsecret::shannon_entropy("abababab"), WithinAbs(1.0, 1e-9));
}

TEST_CASE("regex rule finds a match and ignores clean lines", "[!shouldfail]") {
    unsecret::RegexRule rule("demo", "SECRET_[0-9]{4}");
    REQUIRE(rule.find("token = SECRET_1234").size() == 1);
    REQUIRE(rule.find("nothing to see here").empty());
}

// TODO: add should-match and should-NOT-match tests for every real rule you add.
