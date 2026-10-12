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

Values are masked. A value of 16 or more characters shows its first 4 characters, which
for most tokens is just the public prefix (`AKIA`, `ghp_`). Shorter values are fully
hidden, and the length is never shown.

| Exit code | Meaning |
|---|---|
| 0 | No secrets found |
| 1 | Secrets found (use this to block a commit or fail CI) |
| 2 | Usage or runtime error |

It skips `.git` folders, binary files (a NUL byte in the first 8 KB), files over 1 MB and
symlinks. Files that can't be read are listed as warnings.

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

1. Walk the folder, skipping `.git`, ignored paths, binary and large files.
2. Read each file once and split it into lines.
3. Find every rule keyword on the line in one pass, and run only the rules whose
   keywords are there.
4. Run the entropy rule, and drop its hits where a regex rule already matched.
5. Sort the findings, mask them, print them, and set the exit code.

### Keyword prefilter

Every format rule lists keywords that each of its matches must contain (`akia`, `ghp_`,
`-----begin `...). A hand-written Aho-Corasick automaton finds all of them in one pass over
the line, and a rule's regex only runs when one of its keywords is there. A test runs the
same input with the filter on and off and checks that the findings are identical.

### Long lines

Minified files can have one huge line, and `std::regex` is recursive in all three major
standard libraries. Skipping such lines would leave a blind spot, so they are scanned in
4 KB windows that overlap by more than any match can be long. Each match is reported once,
by the window it starts in.

### Errors

If walking the folder breaks partway, the scan stops with exit code 2 rather than report
a partial scan as clean. Files are read in binary mode (CRLF and a UTF-8 BOM are handled),
paths are printed with `/` and findings are sorted, so the output is the same on every OS.

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
| unsecret | 64.8% | 82.6% | 32.9% |
| Without the entropy rule | 25.5% | 63.4% | 58.2% |
| One entropy threshold (4.5) for every string | 37.5% | 81.7% | 33.4% |

Recall is the share of labelled secrets that unsecret reports. Precision is the share of
its findings that are real secrets, counted two ways: only on lines a person reviewed, and
on all lines with every unreviewed hit counted as wrong. The second is a worst case, since
CredData only reviewed suspicious lines.

### What I found

Hex strings need their own entropy threshold. They use only 16 characters, so their
entropy can never pass 4 bits per character, while base64 can reach 6. With a single
threshold of 4.5, hex keys are invisible. A separate hex threshold of 3.0 raised recall
from 37.5% to 64.8% at the same precision.

The format rules are rarely wrong (private keys 91%, Slack tokens 91%), but together they
find only a quarter of the secrets. Most secrets have no fixed format, and the entropy
rule does most of the work.

Rules tuned on one set of repos did worse on the other. The unquoted-password rule was 88%
precise on the tuning half and 63% on the test half. Without the split, the numbers above
would have looked better than they are.

Treating UUIDs as hex is worth 24 points of recall here, because CredData counts UUIDs
used as keys or tokens as secrets. In code full of ordinary UUID IDs it would add noise.

It still misses passwords on command lines (such as PowerShell `ConvertTo-SecureString`),
in SQL and in curl options, and many vendor-specific formats. Across the whole dataset,
167 files over 1 MB were skipped.

Reproduce it with the manual `credata` workflow in `.github/workflows/`
(CredData commit `0b1940e`, unsecret commit `15a55f9`).

## Speed

On all of CredData (11,398 files), on a GitHub Actions Linux runner (GCC, Release):

| | Speed | Findings |
|---|---|---|
| Keyword prefilter off | 1.8 MB/s | 75,625 |
| Keyword prefilter on | 23.9 MB/s | 75,625 |

The prefilter makes scanning 13.6x faster with the same findings. CredData is a hard case
for it: the dataset was chosen for being full of credentials, so many lines hold a keyword
and the regexes still have to run. On a made-up corpus where 1% of lines hold a keyword,
the speedup was about 60-100x in local runs.

To measure it yourself (it fails if the two runs find different things):

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
