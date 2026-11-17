# PhylaxBox

Privacy-first password manager without a central server: the vault is an encrypted file the
user keeps locally or syncs through their own cloud account.
Product and technical specification: [docs/architecture/specification.md](docs/architecture/specification.md).

## Repository layout

| Path                  | Component | Status |
|-----------------------|-----------|--------|
| `core/crypto/`        | libsodium wrappers: Argon2id, XChaCha20-Poly1305, secure memory | implemented |
| `core/vault/`         | Encrypted container v1 ([format](docs/vault-format/README.md)), compression | implemented |
| `core/storage/`       | Atomic file I/O, local configuration | implemented |
| `core/sync/`          | Cloud storage over an abstract HTTP transport: Dropbox (PKCE OAuth, revision-checked uploads) | Dropbox implemented; Google Drive, merge pending |
| `core/models/`        | Shared types and error hierarchy | vault data model pending (spec §4.5) |
| `desktop/src/`        | Desktop app: webview UI, TLS transport, OAuth loopback listener | UI not wired to the core yet |
| `desktop/frontend/`   | HTML/CSS/JS user interface | placeholder |
| `native-host/`        | Browser Native Messaging host (spec §9) | placeholder |
| `tests/`              | `crypto/` vectors and container, `unit/`, `integration/` (real local sockets) | |
| `docs/`               | `architecture/` spec, `vault-format/` format + test vectors | |
| `tools/vault-reference/` | Independent JS implementation of the format, checks the test vectors | |

Planned, not started: `browser-extension/`, `android/`, `packaging/`, `docs/security/`.

## Prerequisites

* Visual Studio 2022 (MSVC v143) and CMake ≥ 3.25
* [vcpkg](https://github.com/microsoft/vcpkg) cloned somewhere, with `VCPKG_ROOT` pointing to it.
  Dependencies are declared in [`vcpkg.json`](vcpkg.json) (manifest mode) and pinned by `builtin-baseline`;
  they are built automatically on the first configure.

## Build and test

```sh
cmake --preset windows             # core + desktop + native host + tests
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
in the binary), with a one-shot listener on `127.0.0.1:8881`. Access tokens live only in memory.
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

`docs/vault-format/test-vectors/vault-v1.json` is checked by the C++ tests and by an independent JS
implementation in `tools/vault-reference` (`npm install && npm test`).
To regenerate after a deliberate format change:

```sh
build/windows/tests/Release/phylaxbox_core_tests --gtest_also_run_disabled_tests --gtest_filter=*GenerateVectors*
```
