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
| `unquoted-password-assignment` | `PASSWORD=...` without quotes (`.env`, YAML, command lines); the value needs a digit or symbol | Own heuristic |
| `url-credentials` | The password in `scheme://user:password@host` | Own heuristic |
| `high-entropy-string` | Long random-looking words that match no known format | Shannon entropy |

The password and URL rules skip placeholders such as `${DB_PASS}`, `<password>` and
`changeme`. The entropy rule uses a lower threshold for hex strings and UUIDs, which can
never reach the entropy of base64. When an entropy hit overlaps a hit of another rule,
only the other rule is reported.

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

## How well it works

Measured on [CredData](https://github.com/Samsung/CredData), a public benchmark of
open-source code in which people labelled each suspicious line as a real secret or not.
Its real secrets are replaced with fakes of the same shape, so no one's key is exposed.

To avoid grading the tool on the data it was tuned on, the repos were split in two by
their ID. Rules and thresholds were tuned on one half (170 repos). The numbers below come
from the other half (167 repos, 5,545 labelled secrets, 28,803 labelled non-secrets),
measured once, after tuning had stopped.

| | Recall | Precision (labelled lines) | Precision (all lines) |
|---|---|---|---|
| **unsecret** | **64.8%** | **82.6%** | **32.9%** |
| Without the entropy rule | 25.5% | 63.4% | 58.2% |
| One entropy threshold (4.5) for every string | 37.5% | 81.7% | 33.4% |

- **Recall:** the share of labelled secrets that unsecret reports.
- **Precision (labelled lines):** of the findings on lines a person reviewed, the share
  that are real secrets.
- **Precision (all lines):** the same, but counting every finding on an unreviewed line as
  wrong. This is a worst case: CredData only reviewed suspicious lines, so many lines were
  never checked.

What I found:

- **Hex needs its own entropy threshold.** Hex strings use only 16 characters, so their
  entropy can never pass 4 bits per character, while base64 can reach 6. With one threshold
  of 4.5, hex keys are invisible; a separate hex threshold of 3.0 raises recall from 37.5%
  to 64.8% at the same precision.
- **Format rules are precise but rare.** Private keys (91%) and Slack tokens (91%) are
  rarely wrong, but all regex rules together find only a quarter of the secrets. Most
  secrets have no fixed format, so the entropy rule does most of the work.
- **Tuned rules do worse on code they haven't seen.** The unquoted-password rule was 88%
  precise on the tuning half and 63% on the test half. Without the split, the reported
  numbers would have been too good.
- **Treating UUIDs as hex helps here, but depends on the code.** CredData counts UUIDs used
  as keys or tokens as secrets, and on this data the change is worth 24 points of recall.
  In code full of harmless UUID IDs, it adds noise.
- **Still missed:** passwords on command lines (including PowerShell
  `ConvertTo-SecureString`), in SQL and in curl options, and many vendor-specific formats.
  Across the whole dataset, 167 files over 1 MB were skipped.

Reproduce it with the manual `credata` workflow in `.github/workflows/`
(CredData commit `0b1940e`, unsecret commit `15a55f9`).

## Speed

On all of CredData (11,398 files), on a GitHub Actions Linux runner (GCC, Release):

| | Speed | Findings |
|---|---|---|
| Keyword prefilter off | 1.8 MB/s | 75,625 |
| Keyword prefilter on | 23.9 MB/s | 75,625 |

The prefilter makes scanning **13.6x faster** with exactly the same findings. CredData is a
hard case: it was chosen for being full of credentials, so many lines hold a keyword and the
regexes still have to run. On a made-up corpus where 1% of lines hold a keyword, the speedup
was about 60-100x in local runs.

`unsecret_bench` measures this yourself, and fails if the two runs find different things:

```
./build/unsecret_bench              # a made-up 4 MB code-like corpus
./build/unsecret_bench path/to/repo # a real folder
```

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
