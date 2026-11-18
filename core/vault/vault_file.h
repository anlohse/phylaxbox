#ifndef PB_VAULT_FILE_H_
#define PB_VAULT_FILE_H_

#include "crypto/crypto.h"
#include "crypto/secure_bytes.h"
#include "vault/recovery_key.h"

#include <array>
#include <cstdint>
#include <string_view>
#include <vector>

// Encrypted container used for every file PhylaxBox writes.
// Normative description: docs/vault-format/README.md
namespace pb {

enum class content_type : std::uint8_t {
    vault = 1,        // synced password vault (*.phylaxbox)
    local_config = 2, // device-local configuration
};

enum class slot_type : std::uint8_t {
    password = 1,     // KEK = Argon2id(password, salt)
    recovery_key = 2, // KEK = BLAKE2b(key = recovery key, "PhylaxBox recovery slot v1" || salt)
};

using vault_id = std::array<std::uint8_t, 16>;

// One way to unlock the file: the vault key (DEK) wrapped under a KEK.
struct key_slot {
    static constexpr std::size_t SIZE = 100;
    static constexpr std::size_t AD_SIZE = 52; // slot bytes covered by the wrap's AD

    slot_type type = slot_type::password;
    crypto::kdf_params kdf{}; // password slots only; zero for recovery slots
    std::array<std::uint8_t, crypto::SALT_BYTES> salt{};
    std::array<std::uint8_t, crypto::NONCE_BYTES> key_nonce{};
    std::array<std::uint8_t, crypto::KEY_BYTES + crypto::TAG_BYTES> wrapped_key{};
};

struct vault_header {
    static constexpr std::size_t FIXED_SIZE = 40;
    static constexpr std::size_t STABLE_PREFIX = 12; // magic, version, content type, aead id
    static constexpr std::size_t MAX_SLOTS = 4;
    static constexpr std::uint16_t VERSION = 1;
    static constexpr std::uint8_t AEAD_XCHACHA20_POLY1305 = 1;

    content_type type = content_type::vault;
    std::array<std::uint8_t, crypto::NONCE_BYTES> payload_nonce{};
    std::vector<key_slot> slots;

    std::size_t size() const { return FIXED_SIZE + slots.size() * key_slot::SIZE; }
    std::vector<std::uint8_t> serialize() const;

    // Associated data authenticating slot `index`: the stable header prefix
    // plus the slot's own parameters (never the slot count, so slots can be
    // added or removed without re-wrapping the others).
    std::vector<std::uint8_t> slot_ad(std::size_t index) const;

    const key_slot* find(slot_type t) const;

    // Parses and validates the header of `file`. Never runs a KDF.
    // Throws vault_format_exception.
    static vault_header parse(byte_view file, content_type expected);
};

// An unlocked container: holds the vault key in secure memory so the content
// can be re-saved without asking for the password again.
class vault_container {
public:
    // Upper bound for decrypted content (decompression-bomb guard).
    static constexpr std::size_t MAX_CONTENT_SIZE = 64u * 1024u * 1024u;

    // New container with a fresh vault key and vault id, unlockable with
    // `password`. Nothing is written until seal().
    static vault_container create(std::string_view password, content_type type,
                                  const crypto::kdf_params& params = crypto::kdf_params::recommended());

    // Unlocks `file` with the master password and decrypts its content.
    // Throws vault_format_exception, wrong_password_exception or integrity_exception.
    static vault_container open(std::string_view password, byte_view file, content_type expected,
                                secure_bytes& content);

    // Unlocks `file` with the recovery key. Additionally throws
    // pbexception(NO_RECOVERY_SLOT) if the file has no recovery slot.
    static vault_container open_with_recovery_key(const recovery_key& key, byte_view file,
                                                  content_type expected, secure_bytes& content);

    // Encrypts `content` with a fresh payload nonce and the next revision
    // number, and returns the complete file.
    std::vector<std::uint8_t> seal(byte_view content, bool compress = true);

    // Replaces (or adds) the password slot. Other slots stay valid.
    void change_password(std::string_view new_password,
                         const crypto::kdf_params& params = crypto::kdf_params::recommended());

    // Generates a new recovery key, replacing any previous recovery slot.
    // Show the returned key to the user once; it is not stored anywhere.
    recovery_key add_recovery_key();
    void remove_recovery_key(); // requires a password slot to remain

    // True if `password` unwraps this vault's key from the password slot
    // (re-authentication before sensitive actions). Runs the KDF.
    bool check_password(std::string_view password) const;
    bool has_recovery_key() const { return m_header.find(slot_type::recovery_key) != nullptr; }

    // Anti-rollback metadata, authenticated inside the payload.
    // Callers remember (id, revision) per vault and refuse or warn when a
    // later download carries a lower revision for the same id.
    const vault_id& id() const { return m_vault_id; }
    std::uint64_t revision() const { return m_revision; } // of the last file opened/sealed

    // After merging with a remote copy: the next seal() must exceed `revision`.
    void ensure_revision_above(std::uint64_t revision);

    const vault_header& header() const { return m_header; }

    // Decrypts another version of this same vault with the key already in
    // memory — e.g. the remote copy after another device saved it or changed
    // the password — and adopts that version's key slots. No password needed.
    // Returns that version's revision (compare it with revision() BEFORE
    // calling to detect a rollback); afterwards revision() is the maximum of both.
    // Throws vault_format_exception or integrity_exception if `file` is not a
    // version of this vault.
    std::uint64_t reload(byte_view file, secure_bytes& content);

    // Like reload() but changes nothing: decrypts another version of this
    // vault with the key in memory and returns its revision. Used to verify a
    // file before it is written. Same exceptions as reload().
    std::uint64_t read_version(byte_view file, secure_bytes& content) const;

private:
    vault_container(vault_header header, secure_bytes vault_key, const vault_id& id,
                    std::uint64_t revision);

    std::vector<std::uint8_t> seal_with_nonce(byte_view content, bool compress, byte_view nonce);
    void put_slot(key_slot slot, const secure_bytes& kek);

    vault_header m_header;
    secure_bytes m_vault_key;
    vault_id m_vault_id{};
    std::uint64_t m_revision = 0;

    friend struct vault_test_access;
    friend struct vault_container_impl;
};

// Deterministic construction for test vectors ONLY. Never use in the app:
// reusing salts, nonces or keys destroys the security of the format.
struct vault_test_access {
    static vault_container create(std::string_view password, content_type type,
                                  const crypto::kdf_params& params, byte_view salt,
                                  byte_view key_nonce, byte_view vault_key, byte_view vault_id);
    static void add_recovery_key(vault_container& c, const recovery_key& key, byte_view salt,
                                 byte_view key_nonce);
    static std::vector<std::uint8_t> seal(vault_container& c, byte_view content, bool compress,
                                          byte_view payload_nonce);
    static byte_view vault_key(const vault_container& c) { return c.m_vault_key.view(); }
};

} // namespace pb

#endif // PB_VAULT_FILE_H_
