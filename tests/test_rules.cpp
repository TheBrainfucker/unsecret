#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_floating_point.hpp>

#include "unsecret/entropy_rule.hpp"
#include "unsecret/regex_rule.hpp"

using Catch::Matchers::WithinAbs;

// [!shouldfail]: not built yet. Remove the tag once it passes.

TEST_CASE("entropy of a single repeated character is zero") {
    REQUIRE_THAT(unsecret::shannon_entropy("aaaaaaaa"), WithinAbs(0.0, 1e-9));
}

TEST_CASE("entropy of two equally frequent characters is one bit", "[!shouldfail]") {
    REQUIRE_THAT(unsecret::shannon_entropy("abababab"), WithinAbs(1.0, 1e-9));
}

TEST_CASE("regex rule reports position and length of every match") {
    unsecret::RegexRule rule("demo", "SECRET_[0-9]{4}");
    const auto matches = rule.find("a = SECRET_1234, b = SECRET_5678");
    REQUIRE(matches.size() == 2);
    CHECK(matches[0].pos == 4);
    CHECK(matches[0].len == 11);
    CHECK(matches[1].pos == 21);
    CHECK(rule.find("nothing to see here").empty());
}

TEST_CASE("regex rule reports only capture group 1 when the pattern has one") {
    unsecret::RegexRule rule("demo", "key=([a-z]{3})");
    const auto matches = rule.find("x key=abc");
    REQUIRE(matches.size() == 1);
    CHECK(matches[0].pos == 6);
    CHECK(matches[0].len == 3);
}

TEST_CASE("an invalid regex pattern throws when the rule is built") {
    CHECK_THROWS_AS(unsecret::RegexRule("bad", "(unclosed"), std::regex_error);
}

