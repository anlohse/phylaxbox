# PhylaxBox roadmap

Tracks implementation against the [specification](docs/architecture/specification.md)
(phases from §16). Section numbers (§) point to the spec.

**How to use**

- Tick an item (`[x]`) in the same commit or pull request that completes it, and add the
  commit hash or PR link at the end of the line.
- Partially done work stays unticked; note what is missing in the sub-item.
- New work found along the way goes under the right phase (or *Housekeeping*) before it
  is started, so this file stays the single list of what is left.

---

## Phase 1 — Core foundation

- [x] CMake + vcpkg manifest build, presets, pinned baseline — `ad0a010`, `7e6f9d1`
- [x] Repository layout from §13.3 (`core/`, `desktop/`, `native-host/`, `tests/`, `docs/`) — `7e6f9d1`
- [x] Versioned vault file format v1: spec, test vectors, ADR 0001 — `b31992e`
- [x] Argon2id key derivation + XChaCha20-Poly1305 (§4.2) — `ad0a010`
- [x] KEK + DEK envelope with password and recovery-key slots (§4.3, §5.1) — `b31992e`
- [x] Anti-rollback metadata: vault id + revision in the payload (§12.1) — `b31992e`
- [x] JSON content schema 1 with tombstones and forward-compatible fields (§4.5) — `b31992e`
- [x] zlib compression with decompression limits (§4.1) — `ad0a010`
- [x] Local vault persistence: atomic writes, verify before replace, `.bak` (§5.4, §12.4) — `b56c6d4`
- [x] Crypto, container, schema and storage tests; independent JS implementation of the format — `ad0a010`, `b31992e`
- [ ] Keep decrypted entries in secure memory instead of `std::string` (§12.2)
- [ ] Versioned local backups with a retention policy, not just one `.bak` (§5.4)
- [ ] Restore a previous version with integrity check (§5.4)
- [ ] Decide the tombstone retention period (§6.6)
- [ ] Decide the C++ standard: spec says C++20, Saucer requires C++23 (§7.1)

## Phase 2 — Desktop MVP

- [x] Create the vault on first run (password confirmation, loss warning) — `b56c6d4`
- [x] Unlock / lock the vault; Argon2id off the UI thread — `b56c6d4`
- [x] Recovery key: generate, show once, recover and set a new password (§5.3) — `b56c6d4`
- [x] Login screen bridge fix (`window.external.invoke`) — `80d3a0e`
- [ ] Switch the WebView from webview/webview 0.12 to Saucer (§7.1, §7.2)
- [ ] Credential list and details (§7.4)
- [ ] Add, edit and delete credentials (writes entries + tombstones)
- [ ] Search
- [ ] Favorites and tags
- [ ] Copy username / password with clipboard clearing (§12.3)
- [ ] Password and passphrase generator (§7.4)
- [ ] Session management: auto-lock after inactivity (default 5 min), lock with the OS session, optional lock on minimize, re-authentication for sensitive actions (§7.5)
- [ ] Change master password from the UI
- [ ] Manage the recovery key: regenerate / remove
- [ ] Choose or open a vault in another location (§7.4)
- [ ] Settings screen: timeouts, theme, language (§7.4)
- [ ] Accessibility pass: keyboard navigation, labels, contrast (§14.5)

## Phase 3 — Browser integration

- [x] Manifest V3 extension skeleton for Chrome/Edge and Firefox, deterministic packages — `c2df708`
- [ ] Versioned IPC protocol between native host and desktop app: named pipes / Unix sockets (§9.3)
- [ ] Native host: message framing, validation, size limits, fail closed (§9.2, §9.4)
- [ ] Authenticate the native host to the desktop app; authorization per request (§8.4)
- [ ] Fix extension ids (Chrome key, Firefox id) and restrict `allowed_origins`
- [ ] Register the native host from the installers (Windows registry, `NativeMessagingHosts` on Linux)
- [ ] Login form detection and origin-based matching; phishing warnings (§8.5)
- [ ] Autofill into the authorized tab/frame only (§8.6)
- [ ] Save and update credentials from the browser (§8.2)
- [ ] Lint the Firefox package (`web-ext lint`) in CI
- [ ] Chrome Web Store / Firefox Add-ons / Edge Add-ons submissions

## Phase 4 — Cloud synchronization

- [x] Dropbox OAuth 2 with PKCE and a loopback listener (§6.3) — `266c8c9`
- [x] Revision-checked uploads; concurrent saves raise a conflict (§6.5 step 9) — `266c8c9`
- [ ] Move the refresh token to the OS credential store (§6.3); today it is in the encrypted local config
- [ ] Connect / disconnect Dropbox in the UI; revoke the token on disconnect (§6.3)
- [ ] Sync orchestrator: detect changes, debounce, offline queue (§6.2, §6.5)
- [ ] Three-way merge and conflict resolution UI (§6.6)
- [ ] Refuse or warn on rollbacks using the vault revision (§12.1)
- [ ] Google Drive (`drive.file` or `appDataFolder`, §6.4)
- [ ] Register the Dropbox app, set the `DROPBOX_APP_KEY` repository variable, request production status
- [ ] Open the browser for OAuth on Linux and macOS
- [ ] Offline and multi-device tests (§15.2)

## Phase 5 — Hardening and release

- [x] CI on every push: unit tests on Linux and Windows, format vectors — `c2df708`, `09a2230`
- [x] Tag-driven releases: NSIS + ZIP, DEB + TGZ, extension zips, `SHA256SUMS` — `c2df708`, `d0b3e62`
- [x] Release v0.1.0 — `80d3a0e`
- [ ] Choose and add the project LICENSE (installers show a placeholder notice)
- [ ] Sign the Windows installer and executables (SmartScreen)
- [ ] Run desktop tests in CI, including the WebView end-to-end test under a virtual display
- [ ] Static analysis (clang-tidy) and dependency monitoring (Dependabot for Actions and npm) (§14.4)
- [ ] Threat model in `docs/security/` (§12.1)
- [ ] Security review before a public 1.0 (§16 Phase 5)
- [ ] User documentation, privacy policy (stores and OAuth consent screens)
- [ ] Decide the minimum Linux target: the `.deb` is built on Ubuntu 24.04 (glibc ≥ 2.34); consider system OpenSSL for security updates
- [ ] Record the remaining open decisions of §17 as ADRs

## Phase 6 — Mobile and advanced features

- [ ] Android app reading the same vault format, checked against the test vectors (§10)
- [ ] Android Autofill Framework and Credential Manager (§10.3)
- [ ] macOS packaging
- [ ] Passkeys (§11)
- [ ] Additional storage providers, e.g. Nextcloud (§6.1)

## Housekeeping

- [ ] Remove the unused `phylaxboxframework` stub (`desktop/src`)
- [ ] Remove the Parcel placeholder in `desktop/frontend` (`index.html`, `js/`, `package.json`) or turn it into the real frontend build
- [ ] Replace the native host "Hello World" when the IPC protocol exists
- [ ] Silence the unused `argc`/`argv` warnings in `desktop_app.cpp` and the native host

---

## Releases

| Version | Commit | Highlights |
|---------|--------|------------|
| 0.1.0 | `80d3a0e` | Vault format v1, Dropbox client (not wired to the UI), installers and extension skeleton; login screen not yet able to unlock |
