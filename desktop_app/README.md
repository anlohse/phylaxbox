# PhylaxBox desktop

Layout:

| Path         | What |
|--------------|------|
| `src/core/`  | Portable core: crypto (libsodium), encrypted container ([spec](../docs/vault-format.md)), local config. No UI, no network. |
| `src/sync/`  | Cloud storage clients (Dropbox) over an abstract HTTP transport — portable, unit-tested without network. |
| `src/app/`   | Desktop app: webview UI, TLS transport (cpp-httplib), OAuth loopback listener. |
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

## Dropbox

Linking uses OAuth 2 authorization code + PKCE (public client — no app secret
in the binary), with a one-shot listener on `127.0.0.1:8881`. The refresh token
is stored encrypted in the local config; access tokens live only in memory.
Saves are conditional on the last known revision (`rev`), so a concurrent save
from another device raises `sync_conflict_exception` instead of being overwritten.

To enable it in a build:

1. Create an app at <https://www.dropbox.com/developers/apps> with **Scoped access** and **App folder**.
2. Permissions: `files.content.read`, `files.content.write`.
3. OAuth 2 → Redirect URIs: `http://127.0.0.1:8881/phylaxbox/callback`. Allow public clients (PKCE).
4. Configure with the app key: `cmake --preset windows -DPB_DROPBOX_APP_KEY=<app key>`.

Apps start in development status (limited number of linked users); request production
status in the Dropbox console before publishing.

## Test vectors

`docs/test-vectors/vault-v1.json` is checked by the C++ tests and by an independent JS
implementation in `tools/vault-reference` (`npm install && npm test`).
To regenerate after a deliberate format change:

```sh
build/windows/Release/phylaxbox_tests --gtest_also_run_disabled_tests --gtest_filter=*GenerateVectors*
```
