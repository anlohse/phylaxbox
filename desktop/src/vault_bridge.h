#ifndef PB_VAULT_BRIDGE_H_
#define PB_VAULT_BRIDGE_H_

#include "crypto/secure_allocator.h"
#include "file_dialog.h"
#include "storage/device_settings.h"
#include "storage/vault_store.h"

#include <chrono>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>

namespace pb::app {

// Operations the UI calls through the webview bridge. Each takes the JSON
// array of JavaScript arguments and returns the JSON value the JavaScript
// promise resolves with: {"ok": bool, "code": str, "message": str, ...}.
//
// `code` is the contract: the UI translates it (pt-BR / en); `message` is an
// English fallback. Never throws. Passwords reach the page only when the
// user asks to see or edit them; copying goes straight to the clipboard.
// Sensitive account operations re-check the master password. Backups are
// referenced by the names the bridge listed, never by paths from the page.
// Not thread-safe: the desktop app calls it from a single worker thread.
class vault_bridge {
public:
    struct hooks {
        // Puts a secret on the clipboard and clears it after `clear_after`
        // (the app dispatches to the UI thread). Returns false on failure.
        std::function<bool(secure_string&& text, std::chrono::seconds clear_after)> copy_to_clipboard;
        // Called after the vault is locked (e.g. to clear the clipboard).
        std::function<void()> on_lock;
        // Shows a native file dialog (the app runs it on the UI thread and
        // waits). Returns the UTF-8 path, or nullopt when cancelled.
        std::function<std::optional<std::string>(const file_dialog_request&)> choose_file;
    };

    enum class lock_event { session_locked, minimized };

    vault_bridge(vault_store& store, std::string device_id, std::filesystem::path settings_file,
                 hooks h = {});

    // --- session --------------------------------------------------------
    // [] -> {exists, unlocked, vaultPath, isDefaultPath, entries?, hasRecoveryKey?}
    std::string status(const std::string& request);
    // [password, withRecoveryKey] -> {recoveryKey: "XXXXX-..." | null}
    std::string create(const std::string& request);
    // [password] -> {entries}
    std::string unlock(const std::string& request);
    // [recoveryKeyText, newPassword] -> {entries}
    std::string recover(const std::string& request);
    // [] -> {}
    std::string lock(const std::string& request);
    // Locks if the vault preferences ask for it on `event`; true if it locked.
    bool auto_lock(lock_event event);

    // --- vault file -----------------------------------------------------
    // ["open" | "create", dialogTitle, filterName] -> {cancelled} | {path, exists}
    std::string choose_vault(const std::string& request);
    // [] -> {path}
    std::string use_default_vault(const std::string& request);

    // --- entries (vault must be unlocked) -------------------------------
    std::string list(const std::string& request);     // [] -> {entries: [summary...]}
    std::string get(const std::string& request);      // [id] -> {entry}
    std::string reveal(const std::string& request);   // [id] -> {password}
    std::string add(const std::string& request);      // [fields] -> {id}
    std::string update(const std::string& request);   // [id, fields] -> {}
    std::string remove(const std::string& request);   // [id] -> {}
    std::string favorite(const std::string& request); // [id, bool] -> {}
    std::string copy(const std::string& request);     // [id, "username"|"password"] -> {clearsIn}

    // --- settings -------------------------------------------------------
    // [] -> {device: {theme, language, backupRetention}, vault?: {autoLockMinutes,
    //        clipboardClearSeconds, lockOnMinimize, lockOnSessionLock}}
    std::string settings_get(const std::string& request);
    // [{theme?, language?, backupRetention?}] -> {}
    std::string settings_set_device(const std::string& request);
    // [{autoLockMinutes?, clipboardClearSeconds?, lockOnMinimize?, lockOnSessionLock?}] -> {}
    std::string settings_set_vault(const std::string& request);

    // --- account (re-authenticated) ------------------------------------
    // [currentPassword, newPassword] -> {}
    std::string change_password(const std::string& request);
    // [currentPassword] -> {recoveryKey}
    std::string regenerate_recovery_key(const std::string& request);
    // [currentPassword] -> {}
    std::string remove_recovery_key(const std::string& request);

    // --- backups --------------------------------------------------------
    // [] -> {backups: [{name, savedAt, revision, size}]}   (works while locked)
    std::string backups_list(const std::string& request);
    // [currentPassword, name] -> {entries}     unlocked: restore as a new revision
    std::string backup_restore(const std::string& request);
    // [password, name] -> {entries}            locked: the vault file is damaged
    std::string unlock_from_backup(const std::string& request);

    // --- tools ----------------------------------------------------------
    // [{length, lowercase, uppercase, digits, symbols, avoidAmbiguous}] -> {password}
    std::string generate(const std::string& request);
    // [{words, separator, capitalize, includeNumber}] -> {password, bits}
    std::string generate_passphrase(const std::string& request);
    // [] -> {version, wordlist}
    std::string app_info(const std::string& request);

private:
    void save_settings();

    vault_store& m_store;
    std::string m_device_id;
    std::filesystem::path m_settings_file;
    device_settings m_settings;
    hooks m_hooks;
};

} // namespace pb::app

#endif // PB_VAULT_BRIDGE_H_
