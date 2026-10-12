#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "unsecret/keyword_filter.hpp"

using unsecret::KeywordFilter;
using Keywords = std::vector<std::pair<std::string, std::size_t>>;

namespace {

constexpr std::uint64_t bit(std::size_t i) { return std::uint64_t{1} << i; }

}  // namespace

TEST_CASE("keyword filter finds each group's keywords") {
    const KeywordFilter filter(Keywords{{"akia", 0}, {"ghp_", 1}, {"token", 2}});

    CHECK(filter.find("nothing here") == 0);
    CHECK(filter.find("key = AKIA123") == bit(0));
    CHECK(filter.find("ghp_x and token") == (bit(1) | bit(2)));
    CHECK(filter.find("") == 0);
}

TEST_CASE("keyword filter ignores ASCII case") {
    const KeywordFilter filter(Keywords{{"Password", 0}});
    CHECK(filter.find("PASSWORD=") == bit(0));
    CHECK(filter.find("my_password") == bit(0));
}

TEST_CASE("keyword filter finds keywords inside and across each other") {
    // The classic Aho-Corasick case: he, she, his, hers.
    const KeywordFilter filter(Keywords{{"he", 0}, {"she", 1}, {"his", 2}, {"hers", 3}});

    CHECK(filter.find("ushers") == (bit(0) | bit(1) | bit(3)));
    CHECK(filter.find("this") == bit(2));
    CHECK(filter.find("hhe") == bit(0));  // needs the fallback after "hh"
}

TEST_CASE("an empty filter finds nothing") {
    CHECK(KeywordFilter().find("anything") == 0);
    CHECK(KeywordFilter(Keywords{}).find("anything") == 0);
}

TEST_CASE("keyword filter rejects bad input") {
    CHECK_THROWS_AS(KeywordFilter(Keywords{{"x", 64}}), std::out_of_range);
    CHECK_THROWS_AS(KeywordFilter(Keywords{{"", 0}}), std::invalid_argument);
}
