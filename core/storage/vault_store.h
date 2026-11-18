#ifndef PB_VAULT_STORE_H_
#define PB_VAULT_STORE_H_

#include "crypto/crypto.h"
#include "models/vault_document.h"
#include "vault/recovery_key.h"
#include "vault/vault_file.h"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace pb {

// A previous version of the vault kept in the backups directory.
struct vault_backup {
    std::filesystem::path path;
    std::string saved_at;        // RFC 3339 UTC, when it was replaced by a newer version
    std::uint64_t revision = 0;  // vault revision stored in that file
    std::uintmax_t size = 0;
};

// The local vault file (*.phylaxbox) and, while unlocked, its decrypted
// content. Not thread-safe: callers serialize access.
//
// Saving never leaves the only good copy at risk (spec §5.4, §12.4):
//   1. the new file is encrypted and decrypted again in memory;
//   2. the current file is copied to the backups directory (at most once per
//      backup interval, so frequent edits do not flush the history), and the
//      oldest backups beyond the retention count are removed;
//   3. the new file replaces the old one atomically (temp file + rename);
//   4. it is read back and compared byte for byte.
//
// Backups live in <vault dir>/backups/<stem>-<UTC timestamp>-r<revision>.phylaxbox.
// They are encrypted like the vault and open with the same vault key, so they
// stay restorable after the master password changes.
class vault_store {
public:
    static constexpr std::size_t MIN_PASSWORD_CHARS = 8;
    static constexpr std::size_t DEFAULT_BACKUP_RETENTION = 10;
    static constexpr std::chrono::minutes DEFAULT_BACKUP_INTERVAL{15};

    explicit vault_store(std::filesystem::path file = default_path(),
                         crypto::kdf_params kdf = crypto::kdf_params::recommended());

    // <data dir>/vault.phylaxbox (see file_io::default_data_dir()).
    static std::filesystem::path default_path();

    const std::filesystem::path& path() const { return m_path; }
    std::filesystem::path backup_dir() const;
    bool exists() const;
    bool is_unlocked() const { return m_container.has_value(); }

    // How many previous versions to keep (at least 1).
    void set_backup_retention(std::size_t count);
    std::size_t backup_retention() const { return m_backup_retention; }

    // Minimum time between two automatic backups (0: back up on every save).
    void set_backup_interval(std::chrono::seconds interval) { m_backup_interval = interval; }

    // Creates an empty vault and leaves it unlocked. Returns the recovery key
    // when requested (show it once; it is not stored). Throws
    // pbexception(VAULT_EXISTS) if the file exists, pbexception(WEAK_PASSWORD).
    std::optional<recovery_key> create(std::string_view password, bool with_recovery_key);

    // Throws ioexception, vault_format_exception, wrong_password_exception,
    // integrity_exception; for recovery also pbexception(NO_RECOVERY_SLOT).
    void unlock(std::string_view password);
    void unlock_with_recovery_key(const recovery_key& key);

    // Replaces the master password (other key slots stay valid) and saves.
    void change_password(std::string_view new_password);

    // Re-authentication before sensitive actions (runs the KDF, ~1 s).
    bool verify_password(std::string_view password) const;

    // Replaces the recovery key (the old one stops working) and saves.
    // Show the returned key once.
    recovery_key regenerate_recovery_key();
    // Removes the recovery key slot and saves.
    void remove_recovery_key();

    // Points the store at another vault file. Only while locked.
    void set_path(std::filesystem::path file);

    // Encrypts the current document and writes it safely (see above).
    // `force_backup` keeps the replaced version even within the interval
    // (used before restores and password changes, so they can be undone).
    void save(bool force_backup = false);

    // Forgets the key and the decrypted content.
    void lock();

    // Previous versions, newest first. Works while locked (reads names only).
    std::vector<vault_backup> backups() const;

    // Unlocked: brings back the content of `backup` as a new revision (the
    // current version is backed up first, so this can be undone). The backup
    // must decrypt with the key in memory and belong to this vault.
    // Throws integrity_exception / vault_format_exception otherwise.
    void restore_backup(const std::filesystem::path& backup);

    // Locked, for when the vault file itself is damaged: opens `backup` with
    // the master password and makes it the current vault. The damaged file is
    // kept next to it as "<file>.damaged-<UTC timestamp>".
    void unlock_from_backup(std::string_view password, const std::filesystem::path& backup);

    vault_document& document();
    const vault_document& document() const;
    const vault_container& container() const;

    // Unicode code points in a UTF-8 string (what the user perceives as length).
    static std::size_t password_length(std::string_view utf8);

private:
    void require_unlocked() const;
    void load(secure_bytes&& content, vault_container&& container);
    void back_up_current_file();
    void prune_backups() const;

    std::filesystem::path m_path;
    crypto::kdf_params m_kdf;
    std::size_t m_backup_retention = DEFAULT_BACKUP_RETENTION;
    std::chrono::seconds m_backup_interval = DEFAULT_BACKUP_INTERVAL;
    std::optional<vault_container> m_container;
    std::optional<vault_document> m_document;
};

} // namespace pb

#endif // PB_VAULT_STORE_H_
