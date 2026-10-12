#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_floating_point.hpp>

#include <string>
#include <string_view>

#include "unsecret/entropy_rule.hpp"
#include "unsecret/regex_rule.hpp"

using Catch::Matchers::WithinAbs;

namespace {

// Random-looking text, built here so the source holds none.
std::string mixed(std::string_view alphabet, std::size_t length) {
    std::string out;
    for (std::size_t i = 0; i < length; ++i) {
        out += alphabet[(i * 7 + i / alphabet.size()) % alphabet.size()];
    }
    return out;
}

std::string letters_and_digits() {
    std::string out;
    for (char c = 'A'; c <= 'Z'; ++c) out += c;
    for (char c = 'a'; c <= 'z'; ++c) out += c;
    for (char c = '0'; c <= '9'; ++c) out += c;
    return out;
}

}  // namespace

TEST_CASE("entropy of known strings") {
    using unsecret::shannon_entropy;
    CHECK_THAT(shannon_entropy(""), WithinAbs(0.0, 1e-9));
    CHECK_THAT(shannon_entropy("aaaaaaaa"), WithinAbs(0.0, 1e-9));
    CHECK_THAT(shannon_entropy("abababab"), WithinAbs(1.0, 1e-9));
    CHECK_THAT(shannon_entropy("abcd"), WithinAbs(2.0, 1e-9));
    CHECK_THAT(shannon_entropy("0123456789abcdef"), WithinAbs(4.0, 1e-9));
}

TEST_CASE("entropy rule flags random-looking words and reports their place") {
    const unsecret::EntropyRule rule;
    const auto b64 = mixed(letters_and_digits(), 40);
    const auto hex = mixed("0123456789abcdef", 40);

    const auto line = "key = \"" + b64 + "\"";
    const auto matches = rule.find(line);
    REQUIRE(matches.size() == 1);
    CHECK(matches[0].pos == 7);
    CHECK(matches[0].len == 40);

    CHECK(rule.find("sha=" + hex).size() == 1);
}

TEST_CASE("entropy rule ignores normal text, short words and hex below its threshold") {
    const unsecret::EntropyRule rule;
    CHECK(rule.find("const std::string configuration_file_name = load_settings();").empty());
    CHECK(rule.find("this_is_a_rather_long_but_ordinary_identifier").empty());
    CHECK(rule.find(mixed(letters_and_digits(), 19)).empty());  // too short
    CHECK(rule.find("aaaabbbbaaaabbbbaaaabbbb").empty());       // hex, but only 1 bit
}

TEST_CASE("entropy rule thresholds can be changed") {
    const auto word = mixed(letters_and_digits(), 30);
    CHECK(unsecret::EntropyRule(3.0, 4.5, 20).find(word).size() == 1);
    CHECK(unsecret::EntropyRule(3.0, 6.0, 20).find(word).empty());
    CHECK(unsecret::EntropyRule(3.0, 4.5, 31).find(word).empty());
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


TEST_CASE("UUIDs count as hex, so the hex threshold applies") {
    const std::string uuid = "9f1c2b7e" "-4a3d-4c8e-b2f1-7d6e5a4b3c21";
    CHECK(unsecret::is_uuid(uuid));
    CHECK_FALSE(unsecret::is_uuid("9f1c2b7e4a3d4c8e" "b2f17d6e5a4b3c21"));  // no dashes
    CHECK_FALSE(unsecret::is_hex(uuid));

    CHECK(unsecret::EntropyRule().find("id = " + uuid).size() == 1);
    CHECK(unsecret::EntropyRule(3.0, 4.5, 20, false).find("id = " + uuid).empty());
}
