# PhylaxBox desktop

Layout:

| Path         | What |
|--------------|------|
| `src/core/`  | Portable core: crypto (libsodium), encrypted container ([spec](../docs/vault-format.md)), local config. No UI, no network. |
| `src/app/`   | Desktop app: webview UI, cloud sync clients. |
| `tests/`     | GoogleTest unit tests, including the published test vectors. |

## Prerequisites

* Visual Studio 2022 (MSVC v143) and CMake ≥ 3.25
* [vcpkg](https://github.com/microsoft/vcpkg) cloned somewhere, with `VCPKG_ROOT` pointing to it.
  Dependencies are declared in [`vcpkg.json`](vcpkg.json) (manifest mode) and pinned by `builtin-baseline`;
  they are built automatically on the first configure.

## Build and test

```sh
cmake --preset windows             # app + tests
cmake --build --preset windows-release
ctest --preset windows
```

Core only (no OpenSSL / webview), any OS with Ninja:

```sh
cmake --preset core
cmake --build --preset core
ctest --preset core
```

The vcpkg triplet `x64-windows-static-v143` (in `triplets/`) pins the v143 toolset so the
dependencies and the project are compiled by the same MSVC even when a newer Visual Studio
is also installed.

## Test vectors

`docs/test-vectors/vault-v1.json` is checked by the C++ tests and by an independent JS
implementation in `tools/vault-reference` (`npm install && npm test`).
To regenerate after a deliberate format change:

```sh
build/windows/Release/phylaxbox_tests --gtest_also_run_disabled_tests --gtest_filter=*GenerateVectors*
```
