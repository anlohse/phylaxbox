#ifndef PB_CRYPTO_H_
#define PB_CRYPTO_H_

#include "crypto/secure_bytes.h"

#include <cstdint>
#include <string_view>
#include <vector>

// Thin, misuse-resistant wrappers over libsodium. See docs/vault-format/README.md.
namespace pb::crypto {

constexpr std::size_t KEY_BYTES = 32;
constexpr std::size_t SALT_BYTES = 16;
constexpr std::size_t NONCE_BYTES = 24; // XChaCha20-Poly1305
constexpr std::size_t TAG_BYTES = 16;

// Initializes libsodium once (thread-safe). Throws crypto_exception on failure.
void ensure_initialized();

// Fills `out` from the OS CSPRNG.
void random_bytes(std::uint8_t* out, std::size_t size);

// Argon2id v1.3 cost parameters, stored in every file header.
struct kdf_params {
    std::uint32_t opslimit = 0;
    std::uint32_t memlimit_kib = 0;

    static constexpr std::uint32_t MIN_OPSLIMIT = 1;
    static constexpr std::uint32_t MAX_OPSLIMIT = 16;
    static constexpr std::uint32_t MIN_MEMLIMIT_KIB = 8;
    static constexpr std::uint32_t MAX_MEMLIMIT_KIB = 1024u * 1024u; // 1 GiB

    // Parameters for newly created files (t=3, m=64 MiB).
    static kdf_params recommended() { return kdf_params{3, 64u * 1024u}; }

    bool within_limits() const {
        return opslimit >= MIN_OPSLIMIT && opslimit <= MAX_OPSLIMIT &&
               memlimit_kib >= MIN_MEMLIMIT_KIB && memlimit_kib <= MAX_MEMLIMIT_KIB;
    }
};

// Derives a 32-byte key from a (NFC-normalized, UTF-8) password with Argon2id.
// Throws std::invalid_argument for an empty password, a bad salt size or
// out-of-range parameters; crypto_exception if Argon2 fails (e.g. out of memory).
secure_bytes derive_key(std::string_view password, byte_view salt, const kdf_params& params);

// XChaCha20-Poly1305-IETF. Returns ciphertext || tag.
std::vector<std::uint8_t> aead_encrypt(byte_view key, byte_view nonce,
                                       byte_view plaintext, byte_view ad);

// Returns false (and leaves `plaintext` empty) when authentication fails.
bool aead_decrypt(byte_view key, byte_view nonce, byte_view ciphertext,
                  byte_view ad, secure_bytes& plaintext);

} // namespace pb::crypto

#endif // PB_CRYPTO_H_
