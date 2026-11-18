# PhylaxBox

Privacy-first password manager without a central server: the vault is an encrypted file the
user keeps locally or syncs through their own cloud account.
Product and technical specification: [docs/architecture/specification.md](docs/architecture/specification.md).
Progress and what is left: [ROADMAP.md](ROADMAP.md).

## Repository layout

| Path                  | Component | Status |
|-----------------------|-----------|--------|
| `core/crypto/`        | libsodium wrappers: Argon2id, XChaCha20-Poly1305, secure memory | implemented |
| `core/vault/`         | Container v1 ([format](docs/vault-format/README.md)): password + recovery key slots, anti-rollback revision, compression | implemented |
| `core/storage/`       | Local vault file (create, unlock, recovery, verified saves with `.bak`), atomic file I/O, local configuration | implemented |
| `core/sync/`          | Cloud storage over an abstract HTTP transport: Dropbox (PKCE OAuth, revision-checked uploads) | Dropbox implemented; Google Drive, merge pending |
| `core/models/`        | Vault content schema 1 (entries, tombstones), shared types, errors | implemented; merge pending |
| `desktop/src/`        | Desktop app: webview UI, async JS bridge to the vault, TLS transport, OAuth loopback listener | create / unlock / recover / lock |
| `desktop/frontend/`   | `app.html` (embedded in the binary): create vault, recovery key, unlock, recover | entry list pending |
| `native-host/`        | Browser Native Messaging host (spec §9) | placeholder |
| `browser-extension/`  | Manifest V3 extension for Chrome/Edge and Firefox | skeleton: popup + native host status |
| `packaging/`          | CPack installers (Windows NSIS/ZIP, Linux DEB/TGZ) | implemented |
| `tests/`              | `crypto/` vectors and container, `unit/`, `integration/` (real local sockets) | |
| `docs/`               | `architecture/` spec and ADRs, `vault-format/` format + test vectors | |
| `tools/vault-reference/` | Independent JS implementation of the format, checks the test vectors | |

Planned, not started: `android/`, `docs/security/`, macOS packaging.

## Prerequisites

* Windows: Visual Studio 2022 (MSVC v143) and CMake ≥ 3.25
* Linux: GCC ≥ 11, CMake ≥ 3.25, Ninja, `pkg-config autoconf autoconf-archive automake libtool`,
  and for the desktop app `libgtk-3-dev libwebkit2gtk-4.1-dev`
* [vcpkg](https://github.com/microsoft/vcpkg) cloned somewhere, with `VCPKG_ROOT` pointing to it.
  Dependencies are declared in [`vcpkg.json`](vcpkg.json) (manifest mode) and pinned by `builtin-baseline`;
  they are built automatically on the first configure.

## Build and test

```sh
cmake --preset windows             # core + desktop + native host + tests
cmake --build --preset windows-release
ctest --preset windows
```

Windows with Ninja (what CI uses; run from an MSVC v143 developer prompt, e.g.
`vcvarsall.bat x64 -vcvars_ver=14.44`): presets `windows-ninja` and `windows-ninja-core`.

Linux: `cmake --preset linux`, `cmake --build --preset linux`, `ctest --preset linux`.

Core only (no OpenSSL / webview), any OS with Ninja:

```sh
cmake --preset core
cmake --build --preset core
ctest --preset core
```

The vcpkg triplet `x64-windows-static-v143` (in `triplets/`) pins the v143 toolset so the
dependencies and the project are compiled by the same MSVC even when a newer Visual Studio
is also installed.

## Continuous integration and releases

* **Every branch push and pull request** ([ci.yml](.github/workflows/ci.yml)) runs the unit
  tests on Linux and Windows and checks the vault test vectors with the independent JS
  implementation.
* **Pushing a tag `vMAJOR.MINOR.PATCH[-suffix]`** ([release.yml](.github/workflows/release.yml))
  runs the tests, then builds and attaches to a GitHub release:
  * `PhylaxBox-<version>-windows-x64.exe` (NSIS installer) and `.zip` (portable)
  * `phylaxbox_<version>_amd64.deb` (inside, pre-releases use `~`, e.g. `1.1.0~beta.1`, so apt orders them first) and `phylaxbox-<version>-linux-x86_64.tar.gz`
  * `phylaxbox-extension-chrome-<version>.zip` and `phylaxbox-extension-firefox-<version>.zip`
  * `SHA256SUMS.txt`

  The version comes from the tag (`v1.0.0` → `1.0.0`); a suffix (`v1.1.0-beta.1`) marks the
  release as a pre-release. Example:

  ```sh
  git tag v0.1.0
  git push origin v0.1.0
  ```

* The Dropbox app key is read from the repository variable `DROPBOX_APP_KEY`
  (Settings → Secrets and variables → Actions → Variables); builds without it have Dropbox disabled.

Locally: `cpack --config build/windows/CPackConfig.cmake -C Release` (needs NSIS) or
`cpack --config build/linux/CPackConfig.cmake`; `node browser-extension/build.mjs --version 1.0.0 --zip`.

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
