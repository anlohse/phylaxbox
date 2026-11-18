#include "models/vault_preferences.h"

#include <stdexcept>

namespace pb {

namespace {

void read_uint(const secure_json& prefs, const char* key, std::uint32_t lo, std::uint32_t hi,
               std::uint32_t& target) {
    const auto it = prefs.find(key);
    if (it == prefs.end() || !it->is_number_unsigned()) return;
    const auto v = it->get<std::uint64_t>();
    if (v >= lo && v <= hi) target = static_cast<std::uint32_t>(v);
}

void read_bool(const secure_json& prefs, const char* key, bool& target) {
    const auto it = prefs.find(key);
    if (it != prefs.end() && it->is_boolean()) target = it->get<bool>();
}

} // namespace

vault_preferences vault_preferences::from(const vault_document& doc) {
    vault_preferences p;
    if (!doc.preferences.is_object()) return p;
    read_uint(doc.preferences, "autoLockMinutes", MIN_AUTO_LOCK_MINUTES, MAX_AUTO_LOCK_MINUTES,
              p.auto_lock_minutes);
    read_uint(doc.preferences, "clipboardClearSeconds", MIN_CLIPBOARD_SECONDS, MAX_CLIPBOARD_SECONDS,
              p.clipboard_clear_seconds);
    read_bool(doc.preferences, "lockOnMinimize", p.lock_on_minimize);
    read_bool(doc.preferences, "lockOnSessionLock", p.lock_on_session_lock);
    return p;
}

void vault_preferences::validate() const {
    if (auto_lock_minutes < MIN_AUTO_LOCK_MINUTES || auto_lock_minutes > MAX_AUTO_LOCK_MINUTES) {
        throw std::invalid_argument("auto-lock minutes out of range");
    }
    if (clipboard_clear_seconds < MIN_CLIPBOARD_SECONDS || clipboard_clear_seconds > MAX_CLIPBOARD_SECONDS) {
        throw std::invalid_argument("clipboard seconds out of range");
    }
}

void vault_preferences::apply_to(vault_document& doc) const {
    validate();
    if (!doc.preferences.is_object()) doc.preferences = secure_json::object();
    doc.preferences["autoLockMinutes"] = auto_lock_minutes;
    doc.preferences["clipboardClearSeconds"] = clipboard_clear_seconds;
    doc.preferences["lockOnMinimize"] = lock_on_minimize;
    doc.preferences["lockOnSessionLock"] = lock_on_session_lock;
}

} // namespace pb
