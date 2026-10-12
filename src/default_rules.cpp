#include "unsecret/default_rules.hpp"

#include "unsecret/regex_rule.hpp"

namespace unsecret {

std::vector<std::unique_ptr<Rule>> default_rules() {
    std::vector<std::unique_ptr<Rule>> rules;

    // AKIA: access key, ASIA: temporary key. Only the prefix is documented;
    // the length 20 comes from the examples.
    // https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-prefixes
    rules.push_back(std::make_unique<RegexRule>(
        "aws-access-key-id", R"re(\b(?:AKIA|ASIA)[A-Z0-9]{16}\b)re",
        std::vector<std::string>{"akia", "asia"}));

    // No fixed length for ghs_: since April 2026 it can be ghs_APPID_JWT.
    // https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github#githubs-token-formats
    rules.push_back(std::make_unique<RegexRule>(
        "github-token",
        R"re(\b(?:(?:ghp|gho|ghu|ghr)_[A-Za-z0-9]{36,255}|ghs_[A-Za-z0-9_.\-]{36,2048}|github_pat_[A-Za-z0-9_]{22,255})\b)re",
        std::vector<std::string>{"ghp_", "gho_", "ghu_", "ghr_", "ghs_", "github_pat_"}));

    // The last part is the secret: 32 characters, or 6 or 10 on old tokens.
    // https://docs.slack.dev/authentication/tokens
    rules.push_back(std::make_unique<RegexRule>(
        "slack-token",
        R"re(\b(?:xoxb|xoxp|xapp|xwfp|xoxe\.xapp)-(?:[A-Za-z0-9]{1,64}-){1,8}[A-Za-z0-9]{6,64}\b)re",
        std::vector<std::string>{"xoxb-", "xoxp-", "xapp-", "xwfp-"}));

    // RFC 7468, OpenSSL pem.h (RSA, DSA, EC), OpenSSH sshkey.c (OPENSSH).
    rules.push_back(std::make_unique<RegexRule>(
        "private-key-block",
        R"re(-----BEGIN (?:RSA |DSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----)re",
        std::vector<std::string>{"-----begin "}));

    // password = "...". Our own guess, not a vendor format; reports the value only.
    rules.push_back(std::make_unique<RegexRule>(
        "generic-password-assignment",
        R"re((?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)["']?[ \t]{0,8}[:=][ \t]{0,8}["']([^"'\s]{8,128})["'])re",
        std::vector<std::string>{"passw", "pwd", "secret", "api", "token"},
        std::regex::ECMAScript | std::regex::icase));

    return rules;
}

}  // namespace unsecret
