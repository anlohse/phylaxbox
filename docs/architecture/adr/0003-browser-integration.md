# ADR 0003: Browser integration (native host, local IPC, pairing)

Status: accepted · 2026-11-18

The protocol itself is in [docs/browser-integration/protocol.md](../../browser-integration/protocol.md).

## 1. Native messaging host relaying to the running app over local IPC

### Context

Spec §8.3 and §9 call for Native Messaging, a separate lightweight host, and a local
IPC channel to the desktop app (named pipes or Unix sockets), with no HTTP server.
Chromium documents that native messaging is not an authenticated channel by itself.

### Decision

* The host (`native-host/`) is a relay. It checks the shape of each message: size, a
  JSON object, a numeric `id`, and a type from an allow-list.
* It sends a `hello` carrying the extension origin that the browser passed on its
  command line. Requests are forwarded only after that hello.
* The host keeps no state and has no access to the vault.
* The app (`desktop/src/browser_service.cpp`) listens on a per-user endpoint
  (`ipc/local_channel.cpp`). Operating-system access control limits it to the current
  user: a pipe DACL with a first-instance check, or a socket in a private runtime
  directory checked with `SO_PEERCRED`.
* Each connection is one session. Requests run on the same worker thread as the UI's
  requests, so the vault is never accessed concurrently.

### Consequences

* When the app is not running, the host fails closed with `app_unavailable`. The
  extension can ask the host to start the app, which is installed next to it.
* A second app instance does not serve the browser.
* Snap or Flatpak browsers cannot reach `/usr/lib/mozilla` or `/etc/opt/chrome`.
  Supporting them needs their portals and is left for later.

## 2. Authentication: pairing approved in the app, then HMAC challenge-response

### Context

* Spec §8.4 requires that the native host be authenticated to the app, with
  authorization per request, and that the extension be treated as a separate security
  boundary.
* The OS checks keep other users out. They cannot tell the PhylaxBox extension from
  another program running as the same user, or from another browser profile.

### Decision

* On first use, the extension asks to pair. The app shows a dialog with the browser
  name and a 6-digit code, which the popup also shows. The user approves in the app.
* The app then gives the extension a random 32-byte key, bound to its origin. The app
  stores it in `browser-pairings.json` (owner-only, on this device only). The
  extension stores it in `storage.local`.
* Every connection runs a challenge-response with HMAC-SHA256 in both directions, so
  the extension also verifies the app.
* Each paired browser is listed in the app's settings and can be removed.

### Consequences

* The key is stored in plain form on both sides. Malware running as the same user
  could read it, but such malware can already read the browser's memory and the
  user's input. This is the same limit as KeePassXC-Browser's association keys.
  Moving keys to the OS credential store is possible later.
* The key travels once, over the local channel, at approval time. A same-user process
  that impersonates the app at that moment would also have to make the user approve a
  code that never appeared in the real app.
* Closing the native port, which the extension does after 60 s idle, ends the session.
  The next use authenticates again; it is cheap and needs no user action.

## 3. Unlocking from the browser

### Context

Spec §8.2 asks the extension to "request vault unlocking when necessary". We
considered two options:

* bring the desktop window forward and unlock there;
* accept the master password in the popup.

### Decision

The popup accepts the master password, as the project owner chose. It sends the
password to the app over the authenticated session, and the app unlocks the vault
exactly as its own unlock screen does (Argon2id, the same error codes).

### Consequences

* The master password passes through the browser's memory: the popup, the background
  script and the native host's buffers. The host and the app wipe their copies. The
  extension does not keep it, but JavaScript strings cannot be wiped.
* Typing the password in the desktop window instead remains possible.
* Spec §8.4 says that the master password and keys are never *sent to* the extension.
  That still holds: the app never sends them.

## 4. Site matching by registrable domain (Public Suffix List)

### Decision

* Saved addresses match the page when they share a registrable domain under the Public
  Suffix List, compiled into the app and checked by SHA-256 at build time.
* The list includes the private section, so user subdomains on shared hosts stay
  apart.
* `https` entries never match `http` pages.
* IP addresses and single-label hosts need an exact match.
* Filling a login on a page it does not match needs an explicit confirmation after a
  warning that names both sites.

### Consequences

* The app decides what matches; the extension does not. Lists sent to the extension
  never contain passwords.
* The list is a snapshot. Updating it is a documented manual step
  (`core/web/data/README.md`).
* Unicode hosts are converted to punycode without full UTS #46 mapping. Browsers
  already report hosts in that form; saved addresses typed with uppercase non-ASCII
  letters may not match.

## 5. Saving logins: manual by default, automatic detection opt-in

### Context

Spec §8.2 asks the extension to save new logins and update changed passwords. Noticing
a sign-in by itself needs a content script on every site. That means the "read and
change all your data on all websites" permission, and more code running next to
untrusted pages.

### Decision

The project owner chose this option.

* By default, the popup's "Save this login" reads what was typed in the current tab,
  with `activeTab` only.
* Automatic detection is an option in the extension settings. Turning it on requests the
  sites permission at that moment (`optional_host_permissions`) and registers the
  detection scripts. Turning it off unregisters them and gives the permission back.
* The save prompt is a bar in a closed shadow root in the page's top frame. Saving
  requires a trusted click.
* The typed password stays in the background script, never in the popup or the bar,
  for at most 2 minutes.
* The app decides between "add" and "update". It updates only an entry that matches the
  page.

### Consequences

* Installing the extension does not ask for access to all sites.
* With detection on, a page can see that the user typed a password: it always could.
  What the page cannot reach is the bar's content and its buttons.
* A page could cover the bar to make the user click "save". The worst outcome is that
  the password the user just typed on that site gets saved. Backups keep the previous
  version.
* Detection only works for pages opened after it is turned on. It does not detect
  sign-ins while the vault is locked, because the extension would have to hold the
  password until the user unlocks.

## 6. Look-alike domain warnings

Matching by registrable domain already refuses to fill a login on a look-alike site. In
addition, the app compares a page that matches nothing against the saved sites, using
the heuristics in `core/web/lookalike.cpp`. When the page seems to imitate one, the
extension shows a warning that names the real site, both above the logins and in the
save prompts. These are only warnings: legitimate sites can look alike
(`example.com` / `example.com.br`), and blocking them would teach users to ignore the
message.

## 7. Extension identities

* `browser-extension/extension-ids.json` is the single source for the extension
  identities. It holds the Chrome public key (the extension id is derived from it) and
  the Firefox add-on id.
* `build.mjs` writes them into the manifests. CMake writes them into the native host
  manifests and into the app's allow-list.
* The Chrome private key is not in the repository.
* The Chrome Web Store and Edge Add-ons may assign their own ids. Those ids are added
  to the same file when the extension is published.
