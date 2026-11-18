#ifndef PB_VAULT_BRIDGE_H_
#define PB_VAULT_BRIDGE_H_

#include "storage/vault_store.h"

#include <string>

namespace pb::app {

// Operations the UI calls through the webview bridge. Each takes the JSON
// array of JavaScript arguments and returns the JSON value the JavaScript
// promise resolves with: {"ok": bool, "code": str, "message": str, ...}.
//
// Never throws, never echoes secrets back except the freshly generated
// recovery key, and wipes its copies of passwords. Not thread-safe: the
// desktop app calls it from a single worker thread.
class vault_bridge {
public:
    explicit vault_bridge(vault_store& store) : m_store(store) {}

    // [] -> {ok, exists, unlocked, entries?, hasRecoveryKey?}
    std::string status(const std::string& request);
    // [password, withRecoveryKey] -> {ok, recoveryKey: "XXXXX-..." | null}
    std::string create(const std::string& request);
    // [password] -> {ok, entries}
    std::string unlock(const std::string& request);
    // [recoveryKeyText, newPassword] -> {ok, entries}
    std::string recover(const std::string& request);
    // [] -> {ok}
    std::string lock(const std::string& request);

private:
    vault_store& m_store;
};

} // namespace pb::app

#endif // PB_VAULT_BRIDGE_H_
