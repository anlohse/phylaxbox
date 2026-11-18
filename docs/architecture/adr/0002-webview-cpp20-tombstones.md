# ADR 0002 — WebView library, C++ standard, tombstone retention

Status: accepted · 2026-11-18

## 1. WebView: keep webview/webview, not Saucer

### Context

The specification (§7.1) prefers Saucer for the desktop UI. The desktop app
already runs on webview/webview 0.12 (WebView2 on Windows, WebKitGTK on Linux):
the JavaScript → C++ bridge, the asynchronous binding and an end-to-end test
of the real page work on both platforms. Saucer v8 requires C++23 (MSVC
19.44, GCC 14, Clang 20), GTK 4 / webkitgtk-6.0 on Linux and has no vcpkg port.

### Decision

Keep webview/webview. The specification's references to Saucer are updated.

### Consequences

* The Linux package keeps working with GTK 3 / webkit2gtk-4.1, so it runs on
  more distributions than a GTK 4-only build.
* The bridge rules of §7.2 still apply: only explicitly bound functions are
  callable, every request is validated (`desktop/src/vault_bridge.cpp`).
* The page is loaded with `set_html` (an `about:blank` origin); webview has
  no custom schemes. It still has a Content Security Policy, as a `<meta>`
  element: `default-src 'none'`, and only the page's own inline `<script>`
  and `<style>`, allowed by SHA-256 hashes that `desktop/CMakeLists.txt`
  computes at build time (so no `unsafe-inline`, no `eval`, no network). The
  bridge functions and replies are injected by the host, which the policy
  does not restrict. Revisit if the UI grows to load more resources.

## 2. C++ standard: C++20

### Decision

The project builds as C++20 (it was C++17). It is the standard the
specification names, and the toolchains already used in CI support it
(MSVC 14.44 and GCC 13).

### Consequences

* `<chrono>` calendar types replace hand-written date arithmetic
  (`utc_seconds()` in `core/models/vault_document.cpp`).
* With C++20 operator rewriting, `nlohmann::json` must be on the left of
  `==` against other types (e.g. `EXPECT_EQ(json_value, std::string)`), or
  the value converted first.

## 3. Tombstone retention: 180 days

### Context

Deleted entries become tombstones (no secrets: id, deletion time, revision,
device id) so that synchronization does not bring them back (§6.6). Keeping
them forever is safest but grows the file without bound.

### Decision

Tombstones are dropped on save once `deletedAt` is more than 180 days old
(`vault_document::TOMBSTONE_RETENTION`, applied by `vault_store::save()`).

### Consequences

* A device that stays offline for more than 180 days and still holds a
  deleted entry may re-add it when it next synchronizes. The three-way merge
  (§6.6) should treat an entry that reappears after its tombstone was purged
  as a normal addition, and the UI can surface it as "restored by device X".
* The rule is part of the file format description, so every implementation
  purges the same way.
