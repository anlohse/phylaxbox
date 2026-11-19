# Browser integration protocol, version 1

How the PhylaxBox browser extension talks to the desktop app (spec §8, §9).
Decisions and trade-offs: [ADR 0003](../architecture/adr/0003-browser-integration.md).

```
extension ──native messaging (stdio)──▶ native host ──local IPC──▶ desktop app
 (popup,                                 phylaxbox-native-host      (vault, matching,
  background)                                                         pairing UI)
```

* **Native messaging**: the browser starts `phylaxbox-native-host` for the extension and
  exchanges JSON messages, each prefixed with a 32-bit length in native byte order.
  Browsers only start hosts registered for the extension's id
  (`allowed_origins` / `allowed_extensions`, from `browser-extension/extension-ids.json`).
* **Local IPC** (`ipc/local_channel.cpp`): each message is a 32-bit little-endian length
  and UTF-8 JSON, at most 1 MiB.
  * Windows: named pipe `\\.\pipe\phylaxbox.browser.<user SID>.<session id>`. Its DACL
    grants access to the current user only, remote clients are rejected, and the app
    creates it with `FILE_FLAG_FIRST_PIPE_INSTANCE`. The host refuses a pipe owned by
    another user.
  * Linux: Unix socket `$XDG_RUNTIME_DIR/phylaxbox-browser.sock`. Without
    `XDG_RUNTIME_DIR` it is `/tmp/phylaxbox-<uid>/browser.sock`, in a 0700 directory
    whose owner is checked. Both ends check the peer's uid (`SO_PEERCRED`).
* Only one app instance serves the endpoint. A second instance runs without browser
  integration.

## Messages

Every request from the extension is a JSON object with a numeric `id` (a positive
integer) and a `type`. The reply carries the same `id` and has this shape:

```json
{"id": 7, "ok": true, "code": "", "message": "", "...": "..."}
```

* `ok: false` replies carry a stable `code` (listed below), which the extension
  translates.
* `message` is an English fallback.
* Requests are limited to 64 KiB.

### Answered by the native host

| type         | reply |
|--------------|-------|
| `ping`       | `{host: version, protocol: 1}`. Tells the extension the host is installed, even when the app is not running. |
| `launch_app` | Starts the desktop app installed next to the host (a fixed path with no arguments). |

The host refuses any type it does not know (`unknown_type`), including `hello`. It
forwards the types below unchanged.

* If the app is not running, or stops while a request waits, the reply is
  `app_unavailable`.
* The next request opens a new connection to the app, which is a new session.

### Connection handshake (sent by the host, never by the extension)

| request | reply |
|---------|-------|
| `{type: "hello", protocol: 1, origin}` | `{protocol: 1, app: version}`, or `unsupported_protocol` / `origin_not_allowed` |

`origin` is the extension origin reported by the browser:

* `chrome-extension://<id>/` for Chromium browsers;
* the add-on id for Firefox.

The app accepts only the identities listed in `extension-ids.json`.

### Pairing (no authentication needed)

| request | reply |
|---------|-------|
| `{type: "pair_begin", browser}` | `{pairingId, verificationCode: "123 456"}`, or `busy` |
| `{type: "pair_status", pairingId}` | `{state: "pending"}`, `{state: "approved", clientId, key}`, or `pairing_denied` / `pairing_expired` / `too_many_browsers` |

How pairing works:

* `pair_begin` opens a dialog in the app. The dialog shows the browser name and the
  verification code, which the extension also shows.
* The user approves or denies the request in the app. Requests expire after 120 s.
* At most three requests can wait at a time.
* When the request is approved, the app creates a client with a random 32-byte `key`
  (base64) and returns it once. Clients are stored in
  `<data dir>/browser-pairings.json`, readable by the owner only. They stay on this
  device and are never synchronized.
* The extension keeps `{clientId, key}` in `storage.local`.
* The user can remove a paired browser under *Settings → Connected browsers*. The
  removed browser's open sessions stop working on their next request (`not_paired`).

### Authentication

| request | reply |
|---------|-------|
| `{type: "auth_begin", clientId}` | `{challenge}` (32 random bytes, base64), or `not_paired` |
| `{type: "auth_finish", clientId, clientChallenge, proof}` | `{serverProof}`, or `auth_failed` |

The proofs are computed as follows (`‖` is concatenation, `\0` a zero byte):

```
proof       = HMAC-SHA256(key, "phylaxbox-browser-auth-v1\0client\0" ‖ challenge ‖ clientChallenge)
serverProof = HMAC-SHA256(key, "phylaxbox-browser-auth-v1\0server\0" ‖ challenge ‖ clientChallenge)
```

* Each challenge allows one attempt.
* After three failures the app closes the connection.
* The extension checks `serverProof` and refuses an app that cannot produce it
  (`app_not_trusted`).
* A client is bound to the extension origin it was paired from.
* Test vector: key = bytes 0…31, challenge = 0x40…0x5f, clientChallenge = 0x80…0x9f.
  * `proof` is `96ca53da…ba0f8aad`.
  * `serverProof` is `cb321655…f6486d19`.
  * Both sides check it: `tests/unit/browser_protocol_tests.cpp` and
    `browser-extension/test/auth.test.mjs`.

### Authenticated requests

Before authentication these requests get `not_authenticated`. Each one also counts as
activity for the app's auto-lock.

| request | reply |
|---------|-------|
| `{type: "status"}` | `{exists, unlocked}` |
| `{type: "unlock", password}` | `{entries}`, or `wrong_password`, `corrupted`… (the same codes as the app's own unlock) |
| `{type: "lock"}` | `{}` |
| `{type: "matches", url}` | `{site: {host, domain}, entries: [{id, title, username, favorite, match}]}`, or `locked` / `unsupported_page` |
| `{type: "search", query, url?}` | `{entries: [{id, title, username, site, match}], truncated}` (at most 50) |
| `{type: "credentials", entryId, url, allowMismatch?}` | `{username, password, match}`, or `site_mismatch` (with the entry's `site`) / `entry_not_found` |
| `{type: "generate", options: {kind: "password" \| "passphrase", ...}, copy?}` | `{password, bits?, copied?, clearsIn?}` |

* `match` is `exact` (same host), `domain` (same registrable domain) or `none`.
* Lists never contain passwords.
* A password is only returned by `credentials`, for one entry, and only when the entry
  matches `url`. The other way is that the user saw the phishing warning and confirmed
  it (`allowMismatch`).

## Matching (spec §8.5)

The matching code is in `core/web/site_match.cpp`.

* Hosts are compared in ASCII form: lowercase, with Unicode labels converted to
  punycode.
* Two hosts match when they share a registrable domain under the
  [Public Suffix List](../../core/web/data/README.md), including its private section.
  So `accounts.google.com` matches `mail.google.com`, but `alice.github.io` does not
  match `bob.github.io`.
* A saved `https` address never matches an `http` page (no downgrade).
* An address saved without a scheme counts as `https`.
* IP addresses and hosts without a registrable domain (such as `localhost`) need the
  exact host.
* A port in the saved address must match the page's port.

## Filling (spec §8.6)

* The popup and the keyboard shortcut (Ctrl+Shift+L) grant `activeTab` for the current
  tab.
* The background script finds the login fields with `scripting.executeScript`:
  * It fills the top frame, or a frame of the same origin.
  * It refuses login forms that only exist in frames from other origins
    (`untrusted_frame`).
* It asks the app for the credentials, using the URL of that frame.
* It injects them into that frame only, after checking that the frame's origin has not
  changed.
* The password never reaches the popup.
* The form is never submitted.
