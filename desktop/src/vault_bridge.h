#ifndef PB_VAULT_BRIDGE_H_
#define PB_VAULT_BRIDGE_H_

#include "crypto/secure_allocator.h"
#include "storage/vault_store.h"

#include <chrono>
#include <functional>
#include <string>

namespace pb::app {

// Operations the UI calls through the webview bridge. Each takes the JSON
// array of JavaScript arguments and returns the JSON value the JavaScript
// promise resolves with: {"ok": bool, "code": str, "message": str, ...}.
//
// Never throws. Passwords are only sent to the page when the user asks to
// see or edit them (reveal); copying goes straight to the system clipboard.
// Not thread-safe: the desktop app calls it from a single worker thread.
class vault_bridge {
public:
    struct hooks {
        // Puts a secret on the clipboard (the app dispatches it to the UI
        // thread and schedules the clearing). Returns false on failure.
        std::function<bool(secure_string&& text)> copy_to_clipboard;
        // Called after the vault is locked (e.g. to clear the clipboard).
        std::function<void()> on_lock;
    };

    static constexpr std::chrono::seconds CLIPBOARD_CLEAR_AFTER{30};

    vault_bridge(vault_store& store, std::string device_id, hooks h = {})
        : m_store(store), m_device_id(std::move(device_id)), m_hooks(std::move(h)) {}

    // --- session --------------------------------------------------------
    // [] -> {exists, unlocked, entries?, hasRecoveryKey?}
    std::string status(const std::string& request);
    // [password, withRecoveryKey] -> {recoveryKey: "XXXXX-..." | null}
    std::string create(const std::string& request);
    // [password] -> {entries}
    std::string unlock(const std::string& request);
    // [recoveryKeyText, newPassword] -> {entries}
    std::string recover(const std::string& request);
    // [] -> {}
    std::string lock(const std::string& request);

    // --- entries (vault must be unlocked) -------------------------------
    // [] -> {entries: [{id, title, username, urls, tags, favorite, updatedAt}]}
    std::string list(const std::string& request);
    // [id] -> {entry: {id, title, username, urls, application, notes, tags,
    //                  favorite, createdAt, updatedAt, hasPassword}}
    std::string get(const std::string& request);
    // [id] -> {password}
    std::string reveal(const std::string& request);
    // [fields] -> {id}; fields = {title, username, password, urls, application,
    //                             notes, tags, favorite}
    std::string add(const std::string& request);
    // [id, fields] -> {}
    std::string update(const std::string& request);
    // [id] -> {}
    std::string remove(const std::string& request);
    // [id, favorite] -> {}
    std::string favorite(const std::string& request);
    // [id, "username" | "password"] -> {clearsIn: seconds}
    std::string copy(const std::string& request);

    // --- tools ----------------------------------------------------------
    // [{length, lowercase, uppercase, digits, symbols, avoidAmbiguous}] -> {password}
    std::string generate(const std::string& request);

private:
    vault_store& m_store;
    std::string m_device_id;
    hooks m_hooks;
};

} // namespace pb::app

#endif // PB_VAULT_BRIDGE_H_
