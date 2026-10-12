#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "unsecret/default_rules.hpp"
#include "unsecret/scanner.hpp"

// Fake secrets are split up so the source never holds a whole one.

namespace {

const unsecret::Rule& rule(std::string_view id) {
    static const auto rules = unsecret::default_rules();
    for (const auto& r : rules) {
        if (r->id() == id) {
            return *r;
        }
    }
    throw std::logic_error("no rule " + std::string(id));
}

std::vector<std::string> found(std::string_view id, std::string_view line) {
    std::vector<std::string> out;
    for (const auto& m : rule(id).find(line)) {
        out.emplace_back(line.substr(m.pos, m.len));
    }
    return out;
}

using Strings = std::vector<std::string>;

}  // namespace

TEST_CASE("every default rule has a unique id") {
    const auto rules = unsecret::default_rules();
    for (std::size_t i = 0; i < rules.size(); ++i) {
        for (std::size_t j = i + 1; j < rules.size(); ++j) {
            CHECK(rules[i]->id() != rules[j]->id());
        }
    }
}

TEST_CASE("aws-access-key-id") {
    // The example key from the AWS docs.
    const std::string key = std::string("AKIA") + "IOSFODNN7EXAMPLE";
    const std::string temp = std::string("ASIA") + "IOSFODNN7EXAMPLE";

    CHECK(found("aws-access-key-id", "aws_access_key_id = " + key) == Strings{key});
    CHECK(found("aws-access-key-id", "\"" + temp + "\"") == Strings{temp});

    CHECK(found("aws-access-key-id", key + "X").empty());          // too long
    CHECK(found("aws-access-key-id", key.substr(0, 19)).empty());  // too short
    CHECK(found("aws-access-key-id", "x" + key).empty());          // inside a longer word
    CHECK(found("aws-access-key-id", std::string("AKIA") + "iosfodnn7example").empty());
    CHECK(found("aws-access-key-id", std::string("AIDA") + "IOSFODNN7EXAMPLE").empty());  // user ID, not a key
}

TEST_CASE("github-token") {
    const std::string body36(36, 'a');
    const std::string classic = "gh" "p_" + body36;
    const std::string oauth = "gh" "o_" + body36;
    const std::string install_jwt = "gh" "s_12345_" + std::string("eyJhbGciOi.eyJpc3Mi.c2lnbmF0dXJl-_x");
    const std::string fine_grained = "github" "_pat_" + std::string(22, 'A') + "_" + std::string(59, 'b');

    CHECK(found("github-token", "token: " + classic) == Strings{classic});
    CHECK(found("github-token", "'" + oauth + "'") == Strings{oauth});
    CHECK(found("github-token", "GITHUB_TOKEN=" + install_jwt) == Strings{install_jwt});
    CHECK(found("github-token", fine_grained) == Strings{fine_grained});

    CHECK(found("github-token", "gh" "p_" + std::string(35, 'a')).empty());  // too short
    CHECK(found("github-token", "gh" "x_" + body36).empty());                // unknown prefix
    CHECK(found("github-token", "see the ghp_ prefix in the docs").empty());
}

TEST_CASE("slack-token") {
    const std::string bot = "xo" "xb-123456789012-1234567890123-" + std::string(24, 'k');
    const std::string user = "xo" "xp-111-222-333-" + std::string(32, 'd');
    const std::string old_user = "xo" "xp-111-222-333-abcdef";  // 6-character secret, pre-2016
    const std::string rotating = "xo" "xe.xapp-1-A0123-" + std::string(32, 'f');

    CHECK(found("slack-token", "SLACK_BOT_TOKEN=" + bot) == Strings{bot});
    CHECK(found("slack-token", user) == Strings{user});
    CHECK(found("slack-token", old_user) == Strings{old_user});
    CHECK(found("slack-token", rotating) == Strings{rotating});

    CHECK(found("slack-token", "xo" "xb-").empty());
    CHECK(found("slack-token", "xo" "xb-" + std::string(32, 'a')).empty());  // no section separator
    CHECK(found("slack-token", "xo" "xq-111-" + std::string(32, 'a')).empty());
}

TEST_CASE("private-key-block") {
    const std::string begin = "-----BEG" "IN ";
    for (const std::string label : {"PRIVATE KEY", "RSA PRIVATE KEY", "DSA PRIVATE KEY",
                                    "EC PRIVATE KEY", "OPENSSH PRIVATE KEY",
                                    "ENCRYPTED PRIVATE KEY"}) {
        const auto header = begin + label + "-----";
        CHECK(found("private-key-block", header) == Strings{header});
    }

    CHECK(found("private-key-block", begin + "PUBLIC KEY-----").empty());
    CHECK(found("private-key-block", begin + "CERTIFICATE-----").empty());
    CHECK(found("private-key-block", "-----END" " PRIVATE KEY-----").empty());
}

TEST_CASE("generic-password-assignment reports only the value") {
    CHECK(found("generic-password-assignment", "password = \"hunter2hunter2\"") == Strings{"hunter2hunter2"});
    CHECK(found("generic-password-assignment", "\"api_key\": \"abcd1234efgh\"") == Strings{"abcd1234efgh"});
    CHECK(found("generic-password-assignment", "DB_PASSWORD=" "'s3cr3t-value'") == Strings{"s3cr3t-value"});
    CHECK(found("generic-password-assignment", "client_secret: " "'x9y8z7w6v5'") == Strings{"x9y8z7w6v5"});

    CHECK(found("generic-password-assignment", "password = \"short\"").empty());     // under 8 characters
    CHECK(found("generic-password-assignment", "password = \"\"").empty());
    CHECK(found("generic-password-assignment", "password = os.environ[\"DB_PASS\"]").empty());  // not a literal
    CHECK(found("generic-password-assignment", "if (password == input) {").empty());
    CHECK(found("generic-password-assignment", "# reset your password here").empty());
}

TEST_CASE("default rules on a very long line: no stack overflow, secret at the end found") {
    // Like a minified file.
    const std::string key = std::string("AKIA") + "IOSFODNN7EXAMPLE";
    const std::string line = "password = \"" + std::string(256 * 1024, 'a') + " " + key;

    unsecret::Scanner scanner;
    for (auto& r : unsecret::default_rules()) {
        scanner.add_rule(std::move(r));
    }
    std::vector<unsecret::Finding> findings;
    scanner.scan_text(line, "min.js", findings);

    REQUIRE(findings.size() == 1);
    CHECK(findings[0].rule_id == "aws-access-key-id");
    CHECK(findings[0].column == line.size() - key.size() + 1);
}
