#include <catch2/catch_test_macros.hpp>

#include "unsecret/ignore_list.hpp"

using unsecret::glob_match;
using unsecret::IgnoreList;

TEST_CASE("glob: * stays inside one folder, ** crosses folders") {
    CHECK(glob_match("*.js", "app.js"));
    CHECK_FALSE(glob_match("*.js", "lib/app.js"));
    CHECK(glob_match("lib/*.js", "lib/app.js"));
    CHECK(glob_match("**/*.js", "a/b/app.js"));
    CHECK(glob_match("**/*.js", "app.js"));  // ** may be no folder
    CHECK(glob_match("docs/**", "docs/a/b.md"));
    CHECK(glob_match("a?c", "abc"));
    CHECK_FALSE(glob_match("a?c", "a/c"));
    CHECK_FALSE(glob_match("abc", "abcd"));
    CHECK(glob_match("", ""));
}

TEST_CASE("ignore list: names match at any depth, paths from the top") {
    const IgnoreList ignore("*.min.js\nvendor/lib.c\n");

    CHECK(ignore.ignores("app.min.js", false));
    CHECK(ignore.ignores("web/static/app.min.js", false));
    CHECK(ignore.ignores("vendor/lib.c", false));
    CHECK_FALSE(ignore.ignores("src/vendor/lib.c", false));
    CHECK_FALSE(ignore.ignores("app.js", false));
}

TEST_CASE("ignore list: a trailing slash means folders only") {
    const IgnoreList ignore("build/\n/tests/fixtures/\n");

    CHECK(ignore.ignores("build", true));
    CHECK(ignore.ignores("sub/build", true));
    CHECK_FALSE(ignore.ignores("build", false));  // a file named build
    CHECK(ignore.ignores("tests/fixtures", true));
    CHECK_FALSE(ignore.ignores("other/tests/fixtures", true));
}

TEST_CASE("ignore list: comments, blank lines, spaces and CRLF") {
    const IgnoreList ignore("# a comment\r\n\r\n   *.log   \r\n#*.txt\r\n");

    CHECK(ignore.ignores("x.log", false));
    CHECK_FALSE(ignore.ignores("x.txt", false));
    CHECK_FALSE(IgnoreList().ignores("anything", false));
}

TEST_CASE("ignore list: a missing file is an empty list") {
    CHECK_FALSE(IgnoreList::load("no/such/.unsecretignore").ignores("x", false));
}
