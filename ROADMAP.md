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
- [x] Wipe decrypted vault content when freed: zeroing allocator for secret fields and the parsed JSON (§12.2) — `c09007f`
  - [ ] Known gap: the JSON parser's internal token buffer (nlohmann lexer) is freed without wiping
- [x] Versioned local backups in `backups/`, retention by count (default 10) (§5.4) — `c09007f`
  - [x] At most one automatic backup per 15 minutes while editing; restores and password changes always back up — `d2f1398`
- [x] Restore a previous version with integrity check, also when the vault file is damaged (§5.4) — `c09007f`
- [x] Tombstone retention: 180 days, purged on save (§6.6, ADR 0002) — `c09007f`
- [x] C++20 and keep webview/webview instead of Saucer (§7.1, ADR 0002) — `c09007f`

## Phase 2 — Desktop MVP

- [x] Create the vault on first run (password confirmation, loss warning) — `b56c6d4`
- [x] Unlock / lock the vault; Argon2id off the UI thread — `b56c6d4`
- [x] Recovery key: generate, show once, recover and set a new password (§5.3) — `b56c6d4`
- [x] Login screen bridge fix (`window.external.invoke`) — `80d3a0e`
- [x] ~~Switch the WebView to Saucer~~ — dropped: staying on webview/webview (ADR 0002)
- [x] Content Security Policy for the UI: only the page's own inline script and style, by SHA-256 computed at build time; no network, no eval (webview 0.12 has no custom schemes, so the page stays on `about:blank`; ADR 0002) — `6160537`
- [x] Credential list and details; passwords only fetched to reveal or edit (§7.4) — `d2f1398`
- [x] Add, edit and delete credentials (revisions, device id, tombstones; changes rolled back in memory if the save fails) — `d2f1398`
- [x] Search (title, username, sites, tags; Ctrl+F) — `d2f1398`
- [x] Favorites (listed first) and tag filter — `d2f1398`
- [x] Copy username / password through the native clipboard, cleared after 30 s unless replaced; kept out of Windows clipboard history, KDE password hint on Linux (§12.3) — `d2f1398`
  - [x] Warn about other apps reading the clipboard; make the timeout configurable (10–300 s) (§12.3) — `6160537`
- [x] Password generator: CSPRNG, length 8–128, character classes, avoid ambiguous (§7.4) — `d2f1398`
- [x] Passphrase generator: EFF long word list (7,776 words, checked by SHA-256 at build time), 4–20 words, separator, capitals, number, entropy shown (§7.4) — `6160537`
- [x] Auto-lock after 5 minutes without interaction; clipboard cleared on lock and on exit (§7.5) — `d2f1398`; time configurable (1–120 min) — `6160537`
- [x] Lock with the OS session (Windows WTS, logind / screensaver over D-Bus on Linux), optional lock on minimize, current master password required for password / recovery key changes and restores (§7.5) — `6160537`
- [x] Change master password from the UI — `6160537`
- [x] Manage the recovery key: regenerate (shown once) / remove — `6160537`
- [x] Choose or open a vault in another location with the native file dialog; remembered per device (§7.4) — `6160537`
- [x] Settings screen: auto-lock and clipboard timeouts and lock options (stored in the vault), theme and language (stored per device) (§7.4) — `6160537`
- [x] Backups screen: list and restore previous versions, retention setting; restore from a backup when the vault file is damaged (§5.4) — `6160537`
- [x] Accessibility pass: keyboard navigation (list arrows, Ctrl+F, Esc), labels, live status regions, focus outlines, contrast in light and dark themes (§14.5) — `6160537`
- [x] Interface in Portuguese (Brazil) and English, following the system language or the setting; errors translated from the bridge codes — `6160537`

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
