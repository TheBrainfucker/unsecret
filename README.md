# Unsecret

Finds secrets that are no longer secret, before attackers do.

Unsecret is a small C++ command-line tool that scans source code for leaked
credentials such as API keys, tokens and private keys.

## Build

Portable C++20 built with CMake 3.20+. Targets GCC and Clang (Linux, macOS) and
MSVC or MinGW GCC (Windows); no WSL needed.

Linux / macOS:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/unsecret path/to/project
```

Windows with MSVC (Visual Studio or Build Tools, PowerShell):

```powershell
cmake -S . -B build
cmake --build build --config Release
.\build\Release\unsecret.exe path\to\project
```

Windows with MSYS2 (UCRT64 shell, GCC, Ninja):

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/unsecret.exe path/to/project
```

Build with sanitizers (AddressSanitizer + UndefinedBehaviorSanitizer on GCC/Clang;
AddressSanitizer only on MSVC; not available with MinGW):

```sh
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DUNSECRET_SANITIZE=ON
cmake --build build-asan
```

On MSVC use `--config RelWithDebInfo` for the sanitizer build (see the note in
`CMakeLists.txt`).

Run the tests:

```sh
ctest --test-dir build -C Release --output-on-failure
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No secrets found |
| 1 | Secrets found (use this to block a commit or fail CI) |
| 2 | Usage or runtime error |

## Status

Work in progress.