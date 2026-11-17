#include "vault/vault_file.h"

#include "models/pbexceptions.h"
#include "vault/zlibutils.h"

#include <sodium.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>

namespace pb {

namespace {

constexpr char MAGIC[8] = {'P', 'H', 'Y', 'L', 'A', 'X', 'B', 'X'};

constexpr std::uint8_t ENCODING_RAW = 0;
constexpr std::uint8_t ENCODING_ZLIB = 1;
constexpr std::size_t ZLIB_PREFIX = 1 + 8; // encoding + original_length

// Field offsets (docs/vault-format/README.md, "Layout").
constexpr std::size_t OFF_VERSION = 8;
constexpr std::size_t OFF_FLAGS = 10;
constexpr std::size_t OFF_KDF_ID = 12;
constexpr std::size_t OFF_CONTENT_TYPE = 13;
constexpr std::size_t OFF_RESERVED = 14;
constexpr std::size_t OFF_OPSLIMIT = 16;
constexpr std::size_t OFF_MEMLIMIT = 20;
constexpr std::size_t OFF_SALT = 24;
constexpr std::size_t OFF_KEY_NONCE = 40;
constexpr std::size_t OFF_WRAPPED_KEY = 64;
constexpr std::size_t OFF_PAYLOAD_NONCE = 112;
static_assert(OFF_PAYLOAD_NONCE + crypto::NONCE_BYTES == vault_header::SIZE);
static_assert(OFF_KEY_NONCE == vault_header::KEY_AD_SIZE);

void put_u16(std::uint8_t* p, std::uint16_t v) {
    p[0] = static_cast<std::uint8_t>(v);
    p[1] = static_cast<std::uint8_t>(v >> 8);
}
void put_u32(std::uint8_t* p, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) p[i] = static_cast<std::uint8_t>(v >> (8 * i));
}
void put_u64(std::uint8_t* p, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = static_cast<std::uint8_t>(v >> (8 * i));
}
std::uint16_t get_u16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>(p[0] | (p[1] << 8));
}
std::uint32_t get_u32(const std::uint8_t* p) {
    std::uint32_t v = 0;
    for (int i = 3; i >= 0; --i) v = (v << 8) | p[i];
    return v;
}
std::uint64_t get_u64(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
    return v;
}

template <std::size_t N>
void copy_into(std::array<std::uint8_t, N>& dst, byte_view src) {
    if (src.size != N) {
        throw std::invalid_argument("unexpected buffer size");
    }
    std::memcpy(dst.data(), src.data, N);
}

template <std::size_t N>
byte_view view_of(const std::array<std::uint8_t, N>& a) {
    return byte_view(a.data(), N);
}

// Encoded payload = encoding byte [+ original_length] + data (spec: "Encoded payload").
secure_bytes encode_content(byte_view content, bool compress) {
    if (content.size > vault_container::MAX_CONTENT_SIZE) {
        throw std::length_error("content too large");
    }
    if (!compress) {
        secure_bytes out(1 + content.size);
        out.data()[0] = ENCODING_RAW;
        if (content.size) std::memcpy(out.data() + 1, content.data, content.size);
        return out;
    }
    secure_bytes out(ZLIB_PREFIX + zlib::compress_bound(content.size));
    out.data()[0] = ENCODING_ZLIB;
    put_u64(out.data() + 1, content.size);
    const std::size_t n =
        zlib::compress(content, out.data() + ZLIB_PREFIX, out.size() - ZLIB_PREFIX);
    out.truncate(ZLIB_PREFIX + n);
    return out;
}

secure_bytes decode_content(const secure_bytes& encoded) {
    if (encoded.empty()) {
        throw vault_format_exception("empty payload");
    }
    const std::uint8_t encoding = encoded.data()[0];
    if (encoding == ENCODING_RAW) {
        secure_bytes out(encoded.size() - 1);
        if (!out.empty()) std::memcpy(out.data(), encoded.data() + 1, out.size());
        return out;
    }
    if (encoding == ENCODING_ZLIB) {
        if (encoded.size() < ZLIB_PREFIX) {
            throw vault_format_exception("truncated compressed payload");
        }
        const std::uint64_t original = get_u64(encoded.data() + 1);
        if (original > vault_container::MAX_CONTENT_SIZE) {
            throw vault_format_exception("declared content size exceeds the limit");
        }
        secure_bytes out(static_cast<std::size_t>(original));
        zlib::decompress_exact(encoded.view().subview(ZLIB_PREFIX), out.data(), out.size());
        return out;
    }
    throw vault_format_exception("unknown payload encoding " + std::to_string(encoding));
}

} // namespace

// ---------------------------------------------------------------------------
// vault_header
// ---------------------------------------------------------------------------

std::array<std::uint8_t, vault_header::SIZE> vault_header::serialize() const {
    std::array<std::uint8_t, SIZE> h{};
    std::memcpy(h.data(), MAGIC, sizeof MAGIC);
    put_u16(h.data() + OFF_VERSION, version);
    put_u16(h.data() + OFF_FLAGS, 0);
    h[OFF_KDF_ID] = KDF_ARGON2ID13;
    h[OFF_CONTENT_TYPE] = static_cast<std::uint8_t>(type);
    put_u16(h.data() + OFF_RESERVED, 0);
    put_u32(h.data() + OFF_OPSLIMIT, kdf.opslimit);
    put_u32(h.data() + OFF_MEMLIMIT, kdf.memlimit_kib);
    std::memcpy(h.data() + OFF_SALT, salt.data(), salt.size());
    std::memcpy(h.data() + OFF_KEY_NONCE, key_nonce.data(), key_nonce.size());
    std::memcpy(h.data() + OFF_WRAPPED_KEY, wrapped_key.data(), wrapped_key.size());
    std::memcpy(h.data() + OFF_PAYLOAD_NONCE, payload_nonce.data(), payload_nonce.size());
    return h;
}

vault_header vault_header::parse(byte_view file, content_type expected) {
    if (file.size < SIZE + MIN_PAYLOAD_SIZE) {
        throw vault_format_exception("file too short");
    }
    const std::uint8_t* p = file.data;
    if (std::memcmp(p, MAGIC, sizeof MAGIC) != 0) {
        throw vault_format_exception("not a PhylaxBox file");
    }
    vault_header h;
    h.version = get_u16(p + OFF_VERSION);
    if (h.version != VERSION) {
        throw vault_format_exception("unsupported format version " + std::to_string(h.version),
                                     ErrorCodes::UNSUPPORTED_VERSION);
    }
    if (get_u16(p + OFF_FLAGS) != 0 || get_u16(p + OFF_RESERVED) != 0) {
        throw vault_format_exception("reserved header fields are set");
    }
    if (p[OFF_KDF_ID] != KDF_ARGON2ID13) {
        throw vault_format_exception("unknown KDF");
    }
    if (p[OFF_CONTENT_TYPE] != static_cast<std::uint8_t>(expected)) {
        throw vault_format_exception("unexpected content type", ErrorCodes::WRONG_CONTENT_TYPE);
    }
    h.type = expected;
    h.kdf.opslimit = get_u32(p + OFF_OPSLIMIT);
    h.kdf.memlimit_kib = get_u32(p + OFF_MEMLIMIT);
    if (!h.kdf.within_limits()) {
        throw vault_format_exception("KDF parameters out of range");
    }
    copy_into(h.salt, file.subview(OFF_SALT, crypto::SALT_BYTES));
    copy_into(h.key_nonce, file.subview(OFF_KEY_NONCE, crypto::NONCE_BYTES));
    copy_into(h.wrapped_key, file.subview(OFF_WRAPPED_KEY, h.wrapped_key.size()));
    copy_into(h.payload_nonce, file.subview(OFF_PAYLOAD_NONCE, crypto::NONCE_BYTES));
    return h;
}

// ---------------------------------------------------------------------------
// vault_container
// ---------------------------------------------------------------------------

vault_container::vault_container(const vault_header& header, secure_bytes vault_key)
    : m_header(header), m_vault_key(std::move(vault_key)) {}

void vault_container::wrap_key(std::string_view password, const crypto::kdf_params& params,
                               byte_view salt, byte_view key_nonce) {
    vault_header next = m_header;
    next.kdf = params;
    copy_into(next.salt, salt);
    copy_into(next.key_nonce, key_nonce);

    const secure_bytes kek = crypto::derive_key(password, view_of(next.salt), params);
    const auto serialized = next.serialize();
    const auto wrapped = crypto::aead_encrypt(kek, view_of(next.key_nonce), m_vault_key,
                                              byte_view(serialized.data(), vault_header::KEY_AD_SIZE));
    copy_into(next.wrapped_key, wrapped);
    m_header = next;
}

vault_container vault_container::create(std::string_view password, content_type type,
                                        const crypto::kdf_params& params) {
    std::array<std::uint8_t, crypto::SALT_BYTES> salt;
    std::array<std::uint8_t, crypto::NONCE_BYTES> key_nonce;
    secure_bytes vault_key(crypto::KEY_BYTES);
    crypto::random_bytes(salt.data(), salt.size());
    crypto::random_bytes(key_nonce.data(), key_nonce.size());
    crypto::random_bytes(vault_key.data(), vault_key.size());
    return vault_test_access::create(password, type, params, view_of(salt), view_of(key_nonce),
                                     vault_key);
}

vault_container vault_container::open(std::string_view password, byte_view file,
                                      content_type expected, secure_bytes& content) {
    const vault_header header = vault_header::parse(file, expected);
    const auto ad = header.serialize();

    const secure_bytes kek = crypto::derive_key(password, view_of(header.salt), header.kdf);
    secure_bytes vault_key;
    if (!crypto::aead_decrypt(kek, view_of(header.key_nonce), view_of(header.wrapped_key),
                              byte_view(ad.data(), vault_header::KEY_AD_SIZE), vault_key) ||
        vault_key.size() != crypto::KEY_BYTES) {
        throw wrong_password_exception();
    }

    secure_bytes encoded;
    if (!crypto::aead_decrypt(vault_key, view_of(header.payload_nonce),
                              file.subview(vault_header::SIZE), byte_view(ad.data(), ad.size()),
                              encoded)) {
        throw integrity_exception("payload failed authentication (corrupted or tampered file)");
    }
    content = decode_content(encoded);
    return vault_container(header, std::move(vault_key));
}

std::vector<std::uint8_t> vault_container::seal(byte_view content, bool compress) {
    std::array<std::uint8_t, crypto::NONCE_BYTES> nonce;
    crypto::random_bytes(nonce.data(), nonce.size());
    return seal_with_nonce(content, compress, view_of(nonce));
}

std::vector<std::uint8_t> vault_container::seal_with_nonce(byte_view content, bool compress,
                                                           byte_view nonce) {
    vault_header next = m_header;
    copy_into(next.payload_nonce, nonce);
    const auto ad = next.serialize();
    const secure_bytes encoded = encode_content(content, compress);
    const auto ciphertext =
        crypto::aead_encrypt(m_vault_key, nonce, encoded, byte_view(ad.data(), ad.size()));

    std::vector<std::uint8_t> file;
    file.reserve(ad.size() + ciphertext.size());
    file.insert(file.end(), ad.begin(), ad.end());
    file.insert(file.end(), ciphertext.begin(), ciphertext.end());
    m_header = next;
    return file;
}

void vault_container::change_password(std::string_view new_password,
                                      const crypto::kdf_params& params) {
    std::array<std::uint8_t, crypto::SALT_BYTES> salt;
    std::array<std::uint8_t, crypto::NONCE_BYTES> key_nonce;
    crypto::random_bytes(salt.data(), salt.size());
    crypto::random_bytes(key_nonce.data(), key_nonce.size());
    wrap_key(new_password, params, view_of(salt), view_of(key_nonce));
}

// ---------------------------------------------------------------------------
// Deterministic hooks (test vectors only)
// ---------------------------------------------------------------------------

vault_container vault_test_access::create(std::string_view password, content_type type,
                                          const crypto::kdf_params& params, byte_view salt,
                                          byte_view key_nonce, byte_view vault_key) {
    if (vault_key.size != crypto::KEY_BYTES) {
        throw std::invalid_argument("vault key must be 32 bytes");
    }
    secure_bytes key(crypto::KEY_BYTES);
    std::memcpy(key.data(), vault_key.data, crypto::KEY_BYTES);

    vault_header header;
    header.type = type;
    vault_container c(header, std::move(key));
    c.wrap_key(password, params, salt, key_nonce);
    return c;
}

std::vector<std::uint8_t> vault_test_access::seal(vault_container& c, byte_view content,
                                                  bool compress, byte_view payload_nonce) {
    return c.seal_with_nonce(content, compress, payload_nonce);
}

} // namespace pb
