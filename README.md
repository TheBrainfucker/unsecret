# Unsecret

[![build](https://github.com/TheBrainfucker/unsecret/actions/workflows/build.yml/badge.svg)](https://github.com/TheBrainfucker/unsecret/actions/workflows/build.yml)

Finds secrets that are no longer secret, before attackers do.

Unsecret is a small C++20 command-line tool that scans source code for leaked
credentials: API keys, tokens, private keys and hard-coded passwords. It never
prints a full secret, and its exit code can block a commit or fail a CI job.

```
$ unsecret my-project
config/settings.py:2:12 [aws-access-key-id] AKIA********
deploy/id_rsa:1:1 [private-key-block] ----********
src/db.js:3:14 [generic-password-assignment] ********
3 findings in 3 files (scanned 4 files, 154 bytes; skipped 1 ignored)
```

## What it finds

| Rule | Looks for | Based on |
|---|---|---|
| `aws-access-key-id` | `AKIA...` / `ASIA...` access key IDs | [AWS IAM identifiers](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-prefixes) |
| `github-token` | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_` tokens | [GitHub token formats](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github#githubs-token-formats) |
| `slack-token` | `xoxb-`, `xoxp-`, `xapp-`, `xwfp-` tokens | [Slack token types](https://docs.slack.dev/authentication/tokens) |
| `private-key-block` | PEM private key headers (PKCS#8, RSA, DSA, EC, OpenSSH) | RFC 7468, OpenSSL, OpenSSH |
| `generic-password-assignment` | `password = "..."`, `"api_key": "..."` and similar | Own heuristic |
| `high-entropy-string` | Long random-looking words that match no known format | Shannon entropy |

When an entropy hit overlaps a hit of a format rule, only the format rule is reported.

## Usage

```
unsecret <file-or-folder>
```

Each finding prints as `file:line:column [rule] masked-value`, so editors can jump to it.
Findings go to stdout; warnings and the summary go to stderr.

**Masking:** a value of 16 or more characters shows its first 4 characters (for most
tokens that is the public prefix, such as `AKIA` or `ghp_`). Shorter values are fully
hidden. The length is never shown.

**Exit codes:**

| Code | Meaning |
|---|---|
| 0 | No secrets found |
| 1 | Secrets found (use this to block a commit or fail CI) |
| 2 | Usage or runtime error |

**What gets skipped:** `.git` folders, binary files (a NUL byte in the first 8 KB),
files over 1 MB, and symlinks. Files that can't be read are listed as warnings.

### Ignoring files

Put a `.unsecretignore` file in the folder you scan, one pattern per line:

```
# test data with fake keys
tests/fixtures/
*.min.js
```

- `*` matches anything except `/`, `**` matches anything, `?` matches one character.
- A pattern ending in `/` matches folders only, and skips everything inside.
- A pattern with no `/` matches a name at any depth; a pattern with a `/` matches from the
  scanned folder.
- `#` starts a comment. There is no `!` (un-ignore). Matching is case-sensitive.

## How it works

```
walk the folder ─► read each file once ─► split into lines
                                              │
             keyword prefilter (one pass) ◄───┘
                        │  only rules whose keyword is on the line
                        ▼
          regex rules ─► entropy rule (dropped if it overlaps a regex hit)
                        │
                        ▼
              sort ─► mask ─► print ─► exit code
```

A few design choices:

- **Keyword prefilter.** Every format rule lists keywords that each of its matches must
  contain (`akia`, `ghp_`, `-----begin `...). A hand-written Aho-Corasick automaton finds
  all of them in one pass over the line, and a rule's regex only runs when one of its
  keywords is there. A differential test checks that findings are identical with the
  filter on and off.
- **Long lines are scanned in overlapping pieces.** Minified files can have one huge line,
  and `std::regex` is recursive in all three major standard libraries. Instead of skipping
  such lines (a blind spot), they are scanned in 4 KB windows that overlap by more than any
  match can be long; each match is reported once, by the window it starts in.
- **Fails closed.** If walking the folder breaks partway, the scan stops with exit code 2
  instead of reporting a partial scan as clean.
- **Same output on every OS.** Files are read in binary mode (CRLF and a UTF-8 BOM are
  handled), paths are printed with `/`, and findings are sorted.

## Speed

`unsecret_bench` measures scan speed with the prefilter off and on, and fails if the two
runs find different things:

```
./build/unsecret_bench              # a made-up 4 MB code-like corpus
./build/unsecret_bench path/to/repo # a real folder
```

<!-- TODO: add measured results (machine, compiler, corpus) after re-running. -->

<!-- TODO: "What I found" section from the evaluation (unsecret_eval). -->

## Build

C++20 and CMake 3.20+. Built and tested in CI on Linux (GCC, with AddressSanitizer and
UndefinedBehaviorSanitizer), Windows (MSVC) and macOS (Apple Clang).

Linux / macOS:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
./build/unsecret path/to/project
```

Windows with MSVC (PowerShell):

```powershell
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
.\build\Release\unsecret.exe path\to\project
```

Windows with MSYS2 (UCRT64 shell):

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/unsecret.exe path/to/project
```

Sanitizer build (GCC/Clang; not available with MinGW):

```sh
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DUNSECRET_SANITIZE=ON
cmake --build build-asan
ctest --test-dir build-asan --output-on-failure
```

The tests include an end-to-end run of the program and a scan of this repository itself,
which must come back clean. Fake secrets in the tests are put together at runtime, so no
whole secret is ever stored in the repo.

## Limitations

- Scans files on disk only, not git history. A secret deleted in a later commit is still
  in the history.
- Does not check whether a found key is live.
- Patterns use the ECMAScript regex grammar from the C++ standard library (no lookbehind).
- Columns are counted in bytes, not characters.
- On Windows, a path argument with characters outside the current code page may not work.
