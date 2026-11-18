#ifndef PB_VAULT_STORE_H_
#define PB_VAULT_STORE_H_

#include "crypto/crypto.h"
#include "models/vault_document.h"
#include "vault/recovery_key.h"
#include "vault/vault_file.h"

#include <filesystem>
#include <optional>
#include <string_view>

namespace pb {

// The local vault file (*.phylaxbox) and, while unlocked, its decrypted
// content. Not thread-safe: callers serialize access.
//
// Saving never leaves the only good copy at risk (spec §5.4, §12.4):
//   1. the new file is encrypted and decrypted again in memory;
//   2. the current file is copied to "<file>.bak";
//   3. the new file replaces the old one atomically (temp file + rename);
//   4. it is read back and compared byte for byte.
class vault_store {
public:
    static constexpr std::size_t MIN_PASSWORD_CHARS = 8;

    explicit vault_store(std::filesystem::path file = default_path(),
                         crypto::kdf_params kdf = crypto::kdf_params::recommended());

    // <data dir>/vault.phylaxbox (see file_io::default_data_dir()).
    static std::filesystem::path default_path();

    const std::filesystem::path& path() const { return m_path; }
    std::filesystem::path backup_path() const;
    bool exists() const;
    bool is_unlocked() const { return m_container.has_value(); }

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

    // Encrypts the current document and writes it safely (see above).
    void save();

    // Forgets the key and the decrypted content.
    void lock();

    vault_document& document();
    const vault_document& document() const;
    const vault_container& container() const;

    // Unicode code points in a UTF-8 string (what the user perceives as length).
    static std::size_t password_length(std::string_view utf8);

private:
    void require_unlocked() const;
    void load(secure_bytes&& content, vault_container&& container);

    std::filesystem::path m_path;
    crypto::kdf_params m_kdf;
    std::optional<vault_container> m_container;
    std::optional<vault_document> m_document;
};

} // namespace pb

#endif // PB_VAULT_STORE_H_
