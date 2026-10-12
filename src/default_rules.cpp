#include "unsecret/default_rules.hpp"

#include <array>
#include <cctype>
#include <string>

#include "unsecret/entropy_rule.hpp"
#include "unsecret/regex_rule.hpp"

namespace unsecret {

namespace {

std::string lowercase(std::string_view s) {
    std::string out(s);
    for (auto& c : out) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

// Unquoted values are often code (user_password, self.pwd), so ask for a digit or a symbol.
bool looks_like_a_password(std::string_view value) {
    if (looks_like_placeholder(value)) {
        return false;
    }
    for (const char c : value) {
        const auto u = static_cast<unsigned char>(c);
        if (std::isdigit(u) || !(std::isalpha(u) || c == '_' || c == '.' || c == '-')) {
            return true;
        }
    }
    return false;
}

bool not_placeholder(std::string_view value) { return !looks_like_placeholder(value); }

// password, api_key, auth-token...
constexpr const char* secret_names =
    "(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)";

}  // namespace

bool looks_like_placeholder(std::string_view value) {
    if (value.empty()) {
        return true;
    }
    // ${VAR}, $VAR, %(var)s, %VAR%, {{ var }}, <password>
    if (value.front() == '$' || value.front() == '%' || value.front() == '{' ||
        value.front() == '<') {
        return true;
    }
    if (value.find_first_not_of(value.front()) == std::string_view::npos) {
        return true;  // xxxxxxxx, ********
    }
    const auto lower = lowercase(value);
    constexpr std::array exact = {"password", "passwd", "pass", "pwd", "secret", "token",
                                  "user", "username", "none", "null", "undefined"};
    for (const auto* word : exact) {
        if (lower == word) {
            return true;
        }
    }
    constexpr std::array parts = {"changeme", "change_me", "example", "placeholder", "your_",
                                  "your-", "dummy", "sample", "xxx", "***", "..."};
    for (const auto* part : parts) {
        if (lower.find(part) != std::string::npos) {
            return true;
        }
    }
    return false;
}

std::vector<std::unique_ptr<Rule>> default_rules() {
    std::vector<std::unique_ptr<Rule>> rules;

    // AKIA: access key, ASIA: temporary key. Only the prefix is documented;
    // the length 20 comes from the examples.
    // https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-prefixes
    rules.push_back(std::make_unique<RegexRule>(
        "aws-access-key-id", R"re(\b(?:AKIA|ASIA)[A-Z0-9]{16}\b)re",
        RegexOptions{.keywords = {"akia", "asia"}}));

    // No fixed length for ghs_: since April 2026 it can be ghs_APPID_JWT.
    // https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github#githubs-token-formats
    rules.push_back(std::make_unique<RegexRule>(
        "github-token",
        R"re(\b(?:(?:ghp|gho|ghu|ghr)_[A-Za-z0-9]{36,255}|ghs_[A-Za-z0-9_.\-]{36,2048}|github_pat_[A-Za-z0-9_]{22,255})\b)re",
        RegexOptions{.keywords = {"ghp_", "gho_", "ghu_", "ghr_", "ghs_", "github_pat_"}}));

    // The last part is the secret: 32 characters, or 6 or 10 on old tokens.
    // https://docs.slack.dev/authentication/tokens
    rules.push_back(std::make_unique<RegexRule>(
        "slack-token",
        R"re(\b(?:xoxb|xoxp|xapp|xwfp|xoxe\.xapp)-(?:[A-Za-z0-9]{1,64}-){1,8}[A-Za-z0-9]{6,64}\b)re",
        RegexOptions{.keywords = {"xoxb-", "xoxp-", "xapp-", "xwfp-"}}));

    // RFC 7468, OpenSSL pem.h (RSA, DSA, EC), OpenSSH sshkey.c (OPENSSH).
    rules.push_back(std::make_unique<RegexRule>(
        "private-key-block",
        R"re(-----BEGIN (?:RSA |DSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----)re",
        RegexOptions{.keywords = {"-----begin "}}));

    const std::vector<std::string> secret_name_keywords = {"passw", "pwd", "secret", "api",
                                                           "token"};

    // password = "...". Our own guess, not a vendor format; reports the value only.
    rules.push_back(std::make_unique<RegexRule>(
        "generic-password-assignment",
        std::string(secret_names) +
            R"re(["']?[ \t]{0,8}[:=][ \t]{0,8}["']([^"'\s]{8,128})["'])re",
        RegexOptions{.keywords = secret_name_keywords,
                     .flags = std::regex::ECMAScript | std::regex::icase,
                     .keep = not_placeholder}));

    // password=... without quotes, as in .env files, YAML and command lines.
    rules.push_back(std::make_unique<RegexRule>(
        "unquoted-password-assignment",
        std::string(secret_names) +
            R"re([ \t]{0,8}[:=][ \t]{0,8}([^\s"'`=:,;(){}\[\]<>][^\s"'`,;(){}\[\]<>]{7,127}))re",
        RegexOptions{.keywords = secret_name_keywords,
                     .flags = std::regex::ECMAScript | std::regex::icase,
                     .keep = looks_like_a_password}));

    // scheme://user:password@host. Reports the password.
    rules.push_back(std::make_unique<RegexRule>(
        "url-credentials",
        R"re(\b[A-Za-z][A-Za-z0-9+.\-]{1,15}://[^\s/:@"'<>]{1,64}:([^\s/@"'<>]{3,128})@[A-Za-z0-9\[])re",
        RegexOptions{.keywords = {"://"}, .keep = not_placeholder}));

    rules.push_back(std::make_unique<EntropyRule>());

    return rules;
}

}  // namespace unsecret
