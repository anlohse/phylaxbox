#ifndef PB_VAULT_FILE_H_
#define PB_VAULT_FILE_H_

#include "crypto/crypto.h"
#include "crypto/secure_bytes.h"

#include <array>
#include <cstdint>
#include <string_view>
#include <vector>

// Encrypted container used for every file PhylaxBox writes.
// Normative description: docs/vault-format/README.md
namespace pb {

enum class content_type : std::uint8_t {
    vault = 1,        // synced password vault
    local_config = 2, // device-local configuration (sync tokens...)
};

struct vault_header {
    static constexpr std::size_t SIZE = 136;
    static constexpr std::size_t KEY_AD_SIZE = 40; // header[0..40) authenticates the key wrap
    static constexpr std::uint16_t VERSION = 1;
    static constexpr std::uint8_t KDF_ARGON2ID13 = 1;
    static constexpr std::size_t MIN_PAYLOAD_SIZE = crypto::TAG_BYTES + 1;

    std::uint16_t version = VERSION;
    content_type type = content_type::vault;
    crypto::kdf_params kdf;
    std::array<std::uint8_t, crypto::SALT_BYTES> salt{};
    std::array<std::uint8_t, crypto::NONCE_BYTES> key_nonce{};
    std::array<std::uint8_t, crypto::KEY_BYTES + crypto::TAG_BYTES> wrapped_key{};
    std::array<std::uint8_t, crypto::NONCE_BYTES> payload_nonce{};

    std::array<std::uint8_t, SIZE> serialize() const;

    // Parses and validates the header of `file` (steps 1-3 of the reader
    // validation order). Never runs the KDF. Throws vault_format_exception.
    static vault_header parse(byte_view file, content_type expected);
};

// An unlocked container: holds the vault key in secure memory so the content
// can be re-saved without asking for the password again.
class vault_container {
public:
    // Upper bound for decrypted content (decompression-bomb guard).
    static constexpr std::size_t MAX_CONTENT_SIZE = 64u * 1024u * 1024u;

    // New container with a fresh random vault key. Nothing is written until seal().
    static vault_container create(std::string_view password, content_type type,
                                  const crypto::kdf_params& params = crypto::kdf_params::recommended());

    // Unlocks `file` and decrypts its content into `content`.
    // Throws vault_format_exception, wrong_password_exception or integrity_exception.
    static vault_container open(std::string_view password, byte_view file, content_type expected,
                                secure_bytes& content);

    // Encrypts `content` with a fresh payload nonce and returns the complete file.
    std::vector<std::uint8_t> seal(byte_view content, bool compress = true);

    // Re-wraps the vault key under a new password (new salt and key nonce).
    // The previously sealed files stay readable only with the old password;
    // call seal() again to produce a file for the new password.
    void change_password(std::string_view new_password,
                         const crypto::kdf_params& params = crypto::kdf_params::recommended());

    const vault_header& header() const { return m_header; }

private:
    vault_container(const vault_header& header, secure_bytes vault_key);

    std::vector<std::uint8_t> seal_with_nonce(byte_view content, bool compress, byte_view nonce);
    void wrap_key(std::string_view password, const crypto::kdf_params& params, byte_view salt,
                  byte_view key_nonce);

    vault_header m_header;
    secure_bytes m_vault_key;

    friend struct vault_test_access;
};

// Deterministic construction for test vectors ONLY. Never use in the app:
// reusing salts, nonces or keys destroys the security of the format.
struct vault_test_access {
    static vault_container create(std::string_view password, content_type type,
                                  const crypto::kdf_params& params, byte_view salt,
                                  byte_view key_nonce, byte_view vault_key);
    static std::vector<std::uint8_t> seal(vault_container& c, byte_view content, bool compress,
                                          byte_view payload_nonce);
};

} // namespace pb

#endif // PB_VAULT_FILE_H_
