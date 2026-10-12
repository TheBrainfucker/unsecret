#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <random>
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

TEST_CASE("the prefilter never changes the findings") {
    // Random lines built from rule pieces, so real hits and near misses both show up.
    const std::vector<std::string> pieces = {
        "AK" "IA", "AS" "IA", "IOSFODNN7EXAMPLE", "gh" "p_", "gh" "s_", "github" "_pat_",
        "xo" "xb-", "xo" "xe.xapp-", "123-", "-----BEG" "IN ", "RSA ", "PRIVATE KEY-----",
        "Pass" "word", "api_key", "TOKEN", "secret", " = ", ": ", "\"", "'", " ",
        std::string(16, 'a'), std::string(32, 'Z'), "x", "_", "-", ".", "9"};

    std::mt19937 random(12345);
    std::uniform_int_distribution<std::size_t> pick(0, pieces.size() - 1);
    std::uniform_int_distribution<int> length(1, 30);
    std::string text;
    for (int line = 0; line < 3000; ++line) {
        for (int n = length(random); n > 0; --n) {
            text += pieces[pick(random)];
        }
        text += '\n';
    }

    auto scan = [&](bool prefilter) {
        unsecret::Scanner scanner;
        for (auto& r : unsecret::default_rules()) {
            scanner.add_rule(std::move(r));
        }
        scanner.use_prefilter(prefilter);
        std::vector<unsecret::Finding> findings;
        scanner.scan_text(text, "random.txt", findings);
        return findings;
    };

    const auto with = scan(true);
    const auto without = scan(false);
    CHECK(with.size() > 100);  // the test is only useful if things are found
    CHECK(with == without);
}

TEST_CASE("placeholders are recognised") {
    using unsecret::looks_like_placeholder;
    for (const char* value : {"${DB_PASSWORD}", "$PASS", "%(password)s", "{{ secret }}",
                              "<password>", "xxxxxxxx", "********", "changeme123",
                              "your_api_key_here", "Password", "example-token"}) {
        CHECK(looks_like_placeholder(value));
    }
    for (const char* value : {"hunter2hunter2", "s3cr3t-value", "Tr0ub4dor&3"}) {
        CHECK_FALSE(looks_like_placeholder(value));
    }
}

TEST_CASE("generic-password-assignment skips placeholders") {
    CHECK(found("generic-password-assignment", "password = \"${DB_PASSWORD}\"").empty());
    CHECK(found("generic-password-assignment", "api_key: \"your_api_key_here\"").empty());
}

TEST_CASE("unquoted-password-assignment") {
    CHECK(found("unquoted-password-assignment", "DB_PASSWORD=" "hunter2hunter2") == Strings{"hunter2hunter2"});
    CHECK(found("unquoted-password-assignment", "  password: " "S3cure!pass") == Strings{"S3cure!pass"});
    CHECK(found("unquoted-password-assignment", "mysql --password=" "Tr0ub4dor3 db") == Strings{"Tr0ub4dor3"});

    CHECK(found("unquoted-password-assignment", "password = user_password").empty());  // code, no digit
    CHECK(found("unquoted-password-assignment", "password = self.password").empty());
    CHECK(found("unquoted-password-assignment", "pwd = get_pwd(name2)").empty());       // a call
    CHECK(found("unquoted-password-assignment", "if (password == input2) {").empty());
    CHECK(found("unquoted-password-assignment", "un" "secret::Scanner scanner;").empty());
    CHECK(found("unquoted-password-assignment", "PASSWORD=${DB_PASS}").empty());
    CHECK(found("unquoted-password-assignment", "password = \"quoted123\"").empty());   // the quoted rule's job
}

TEST_CASE("url-credentials reports the password") {
    const std::string url = "postgres://app:" + std::string("S3cretPass") + "@db.local:5432/x";
    CHECK(found("url-credentials", "DATABASE_URL=" + url) == Strings{"S3cretPass"});
    CHECK(found("url-credentials", "https://user:" + std::string("tok3n_abc") + "@github.com/a/b") ==
          Strings{"tok3n_abc"});

    CHECK(found("url-credentials", "https://example.com/path").empty());
    CHECK(found("url-credentials", "https://user@example.com").empty());              // no password
    CHECK(found("url-credentials", "postgres://app:" "password@localhost/x").empty());  // placeholder
    CHECK(found("url-credentials", "redis://:${REDIS_PASS}@cache:6379").empty());
}
