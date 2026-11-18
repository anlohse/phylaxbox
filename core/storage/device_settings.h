#ifndef PB_DEVICE_SETTINGS_H_
#define PB_DEVICE_SETTINGS_H_

#include <cstddef>
#include <filesystem>
#include <string>

namespace pb {

// Settings of this computer, needed before the vault is unlocked. Not
// secret: stored as plain JSON in <data dir>/settings.json. Security
// settings that should follow the user (auto-lock, clipboard) live in the
// vault instead (vault_preferences).
struct device_settings {
    static constexpr std::size_t MIN_BACKUP_RETENTION = 1;
    static constexpr std::size_t MAX_BACKUP_RETENTION = 100;

    std::string theme = "system";    // "system" | "light" | "dark"
    std::string language = "system"; // "system" | "pt-BR" | "en"
    std::string vault_path;          // UTF-8; empty: vault_store::default_path()
    std::size_t backup_retention = 10;

    // Missing or unreadable file, or invalid fields: defaults (field by field).
    static device_settings load(const std::filesystem::path& file);
    // Throws std::invalid_argument for invalid values, ioexception on write errors.
    void save(const std::filesystem::path& file) const;
    void validate() const;

    static std::filesystem::path default_path();
    // vault_path as a filesystem path, or the default vault location.
    std::filesystem::path effective_vault_path() const;
};

} // namespace pb

#endif // PB_DEVICE_SETTINGS_H_
