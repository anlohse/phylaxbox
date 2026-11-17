#include "crypto/crypto.h"

#include "models/pbexceptions.h"

#include <sodium.h>

#include <new>
#include <stdexcept>
#include <utility>

namespace pb {

// ---------------------------------------------------------------------------
// byte_view / secure_bytes
// ---------------------------------------------------------------------------

byte_view byte_view::subview(std::size_t offset, std::size_t count) const {
    if (offset > size || count > size - offset) {
        throw std::out_of_range("byte_view::subview out of range");
    }
    return byte_view(data + offset, count);
}

byte_view byte_view::subview(std::size_t offset) const {
    if (offset > size) {
        throw std::out_of_range("byte_view::subview out of range");
    }
    return byte_view(data + offset, size - offset);
}

secure_bytes::secure_bytes(std::size_t size) {
    if (size == 0) {
        return;
    }
    crypto::ensure_initialized();
    m_data = static_cast<std::uint8_t*>(sodium_malloc(size));
    if (m_data == nullptr) {
        throw std::bad_alloc();
    }
    sodium_memzero(m_data, size);
    m_size = size;
}

secure_bytes::~secure_bytes() { release(); }

secure_bytes::secure_bytes(secure_bytes&& other) noexcept
    : m_data(std::exchange(other.m_data, nullptr)), m_size(std::exchange(other.m_size, 0)) {}

secure_bytes& secure_bytes::operator=(secure_bytes&& other) noexcept {
    if (this != &other) {
        release();
        m_data = std::exchange(other.m_data, nullptr);
        m_size = std::exchange(other.m_size, 0);
    }
    return *this;
}

void secure_bytes::truncate(std::size_t new_size) {
    if (new_size > m_size) {
        throw std::out_of_range("secure_bytes::truncate cannot grow");
    }
    sodium_memzero(m_data + new_size, m_size - new_size);
    m_size = new_size;
}

void secure_bytes::release() noexcept {
    if (m_data != nullptr) {
        sodium_free(m_data); // wipes before freeing
        m_data = nullptr;
        m_size = 0;
    }
}

namespace crypto {

static_assert(KEY_BYTES == crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
static_assert(NONCE_BYTES == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
static_assert(TAG_BYTES == crypto_aead_xchacha20poly1305_ietf_ABYTES);
static_assert(SALT_BYTES == crypto_pwhash_argon2id_SALTBYTES);
static_assert(kdf_params::MIN_MEMLIMIT_KIB * 1024u >= crypto_pwhash_argon2id_MEMLIMIT_MIN);
static_assert(kdf_params::MIN_OPSLIMIT >= crypto_pwhash_argon2id_OPSLIMIT_MIN);

void ensure_initialized() {
    // Function-local static: initialized exactly once, thread-safe.
    static const bool initialized = [] { return sodium_init() >= 0; }();
    if (!initialized) {
        throw crypto_exception("libsodium initialization failed");
    }
}

void random_bytes(std::uint8_t* out, std::size_t size) {
    ensure_initialized();
    randombytes_buf(out, size);
}

secure_bytes derive_key(std::string_view password, byte_view salt, const kdf_params& params) {
    ensure_initialized();
    if (password.empty()) {
        throw std::invalid_argument("password must not be empty");
    }
    if (password.size() > crypto_pwhash_argon2id_PASSWD_MAX) {
        throw std::invalid_argument("password too long");
    }
    if (salt.size != SALT_BYTES) {
        throw std::invalid_argument("salt must be 16 bytes");
    }
    if (!params.within_limits()) {
        throw std::invalid_argument("KDF parameters out of range");
    }

    secure_bytes key(KEY_BYTES);
    const std::size_t memlimit_bytes = static_cast<std::size_t>(params.memlimit_kib) * 1024u;
    if (crypto_pwhash(key.data(), key.size(), password.data(), password.size(), salt.data,
                      params.opslimit, memlimit_bytes, crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw crypto_exception("Argon2id key derivation failed (out of memory?)");
    }
    return key;
}

secure_bytes keyed_hash(byte_view key, byte_view message) {
    ensure_initialized();
    if (key.size < crypto_generichash_KEYBYTES_MIN || key.size > crypto_generichash_KEYBYTES_MAX) {
        throw std::invalid_argument("keyed_hash: bad key size");
    }
    secure_bytes out(KEY_BYTES);
    if (crypto_generichash(out.data(), out.size(), message.data, message.size, key.data,
                           key.size) != 0) {
        throw crypto_exception("BLAKE2b failed");
    }
    return out;
}

std::vector<std::uint8_t> aead_encrypt(byte_view key, byte_view nonce, byte_view plaintext,
                                       byte_view ad) {
    ensure_initialized();
    if (key.size != KEY_BYTES || nonce.size != NONCE_BYTES) {
        throw std::invalid_argument("aead_encrypt: bad key or nonce size");
    }
    std::vector<std::uint8_t> out(plaintext.size + TAG_BYTES);
    unsigned long long out_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(out.data(), &out_len, plaintext.data,
                                                   plaintext.size, ad.data, ad.size, nullptr,
                                                   nonce.data, key.data) != 0) {
        throw crypto_exception("AEAD encryption failed");
    }
    out.resize(static_cast<std::size_t>(out_len));
    return out;
}

bool aead_decrypt(byte_view key, byte_view nonce, byte_view ciphertext, byte_view ad,
                  secure_bytes& plaintext) {
    ensure_initialized();
    plaintext = secure_bytes();
    if (key.size != KEY_BYTES || nonce.size != NONCE_BYTES) {
        throw std::invalid_argument("aead_decrypt: bad key or nonce size");
    }
    if (ciphertext.size < TAG_BYTES) {
        return false;
    }
    secure_bytes out(ciphertext.size - TAG_BYTES);
    unsigned long long out_len = 0;
    // sodium_malloc(0) is avoided by secure_bytes; libsodium accepts a null
    // output pointer when the message is empty.
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(out.data(), &out_len, nullptr,
                                                   ciphertext.data, ciphertext.size, ad.data,
                                                   ad.size, nonce.data, key.data) != 0) {
        return false;
    }
    plaintext = std::move(out);
    return true;
}

} // namespace crypto
} // namespace pb
