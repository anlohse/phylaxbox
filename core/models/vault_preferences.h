#ifndef PB_VAULT_PREFERENCES_H_
#define PB_VAULT_PREFERENCES_H_

#include "models/vault_document.h"

#include <cstdint>

namespace pb {

// Security settings stored inside the (encrypted) vault, so they follow the
// user to every device: document.preferences keys autoLockMinutes,
// clipboardClearSeconds, lockOnMinimize, lockOnSessionLock. Other keys in
// preferences are preserved.
struct vault_preferences {
    static constexpr std::uint32_t MIN_AUTO_LOCK_MINUTES = 1;
    static constexpr std::uint32_t MAX_AUTO_LOCK_MINUTES = 120;
    static constexpr std::uint32_t MIN_CLIPBOARD_SECONDS = 10;
    static constexpr std::uint32_t MAX_CLIPBOARD_SECONDS = 300;

    std::uint32_t auto_lock_minutes = 5;      // spec §7.5 default
    std::uint32_t clipboard_clear_seconds = 30;
    bool lock_on_minimize = false;
    bool lock_on_session_lock = true;

    // Missing or invalid values: defaults (field by field).
    static vault_preferences from(const vault_document& doc);
    // Throws std::invalid_argument for out-of-range values.
    void validate() const;
    void apply_to(vault_document& doc) const;
};

} // namespace pb

#endif // PB_VAULT_PREFERENCES_H_
