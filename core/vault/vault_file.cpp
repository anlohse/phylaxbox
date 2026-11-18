#include "vault/vault_file.h"

#include "models/pbexceptions.h"
#include "vault/zlibutils.h"

#include <sodium.h>

#include <algorithm>
#include <cstring>
#include <functional>
#include <stdexcept>
#include <string>
#include <utility>

namespace pb {

namespace {

constexpr char MAGIC[8] = {'P', 'H', 'Y', 'L', 'A', 'X', 'B', 'X'};
constexpr char RECOVERY_CONTEXT[] = "PhylaxBox recovery slot v1";

// Fixed header offsets (docs/vault-format/README.md, "Layout").
constexpr std::size_t OFF_VERSION = 8;
constexpr std::size_t OFF_CONTENT_TYPE = 10;
constexpr std::size_t OFF_AEAD_ID = 11;
constexpr std::size_t OFF_FLAGS = 12;
constexpr std::size_t OFF_SLOT_COUNT = 14;
constexpr std::size_t OFF_RESERVED = 15;
constexpr std::size_t OFF_PAYLOAD_NONCE = 16;
static_assert(OFF_PAYLOAD_NONCE + crypto::NONCE_BYTES == vault_header::FIXED_SIZE);

// Key slot offsets, relative to the slot.
constexpr std::size_t SLOT_TYPE = 0;
constexpr std::size_t SLOT_RESERVED = 1; // 3 bytes
constexpr std::size_t SLOT_OPSLIMIT = 4;
constexpr std::size_t SLOT_MEMLIMIT = 8;
constexpr std::size_t SLOT_SALT = 12;
constexpr std::size_t SLOT_KEY_NONCE = 28;
constexpr std::size_t SLOT_WRAPPED_KEY = 52;
static_assert(SLOT_WRAPPED_KEY == key_slot::AD_SIZE);
static_assert(SLOT_WRAPPED_KEY + crypto::KEY_BYTES + crypto::TAG_BYTES == key_slot::SIZE);

// Encoded payload (plaintext inside the AEAD).
constexpr std::size_t PAYLOAD_PREFIX = 16 + 8 + 1; // vault_id, revision, encoding
constexpr std::uint8_t ENCODING_RAW = 0;
constexpr std::uint8_t ENCODING_ZLIB = 1;
constexpr std::size_t MIN_PAYLOAD_CIPHERTEXT = PAYLOAD_PREFIX + crypto::TAG_BYTES;

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

template <std::size_t N>
std::array<std::uint8_t, N> random_array() {
    std::array<std::uint8_t, N> a{};
    crypto::random_bytes(a.data(), N);
    return a;
}

void write_stable_prefix(std::uint8_t* p, content_type type) {
    std::memcpy(p, MAGIC, sizeof MAGIC);
    put_u16(p + OFF_VERSION, vault_header::VERSION);
    p[OFF_CONTENT_TYPE] = static_cast<std::uint8_t>(type);
    p[OFF_AEAD_ID] = vault_header::AEAD_XCHACHA20_POLY1305;
}

void write_slot(std::uint8_t* p, const key_slot& s) {
    std::memset(p, 0, key_slot::SIZE);
    p[SLOT_TYPE] = static_cast<std::uint8_t>(s.type);
    put_u32(p + SLOT_OPSLIMIT, s.kdf.opslimit);
    put_u32(p + SLOT_MEMLIMIT, s.kdf.memlimit_kib);
    std::memcpy(p + SLOT_SALT, s.salt.data(), s.salt.size());
    std::memcpy(p + SLOT_KEY_NONCE, s.key_nonce.data(), s.key_nonce.size());
    std::memcpy(p + SLOT_WRAPPED_KEY, s.wrapped_key.data(), s.wrapped_key.size());
}

std::vector<std::uint8_t> slot_ad_for(content_type type, const key_slot& s) {
    std::vector<std::uint8_t> ad(vault_header::STABLE_PREFIX + key_slot::SIZE);
    write_stable_prefix(ad.data(), type);
    write_slot(ad.data() + vault_header::STABLE_PREFIX, s);
    ad.resize(vault_header::STABLE_PREFIX + key_slot::AD_SIZE); // drop wrapped_key
    return ad;
}

secure_bytes recovery_kek(const recovery_key& key, byte_view salt) {
    std::vector<std::uint8_t> msg(RECOVERY_CONTEXT, RECOVERY_CONTEXT + sizeof RECOVERY_CONTEXT - 1);
    msg.insert(msg.end(), salt.data, salt.data + salt.size);
    return crypto::keyed_hash(key.bytes(), msg);
}

secure_bytes kek_for_slot(const key_slot& s, std::string_view password) {
    return crypto::derive_key(password, view_of(s.salt), s.kdf);
}

// Encoded payload = vault_id | revision | encoding [| original_length] | data.
secure_bytes encode_payload(const vault_id& id, std::uint64_t revision, byte_view content,
                            bool compress) {
    if (content.size > vault_container::MAX_CONTENT_SIZE) {
        throw std::length_error("content too large");
    }
    const std::size_t body_capacity =
        compress ? 8 + zlib::compress_bound(content.size) : content.size;
    secure_bytes out(PAYLOAD_PREFIX + body_capacity);
    std::memcpy(out.data(), id.data(), id.size());
    put_u64(out.data() + 16, revision);
    out.data()[24] = compress ? ENCODING_ZLIB : ENCODING_RAW;
    if (!compress) {
        if (content.size) std::memcpy(out.data() + PAYLOAD_PREFIX, content.data, content.size);
        return out;
    }
    put_u64(out.data() + PAYLOAD_PREFIX, content.size);
    const std::size_t n = zlib::compress(content, out.data() + PAYLOAD_PREFIX + 8,
                                         out.size() - PAYLOAD_PREFIX - 8);
    out.truncate(PAYLOAD_PREFIX + 8 + n);
    return out;
}

struct decoded_payload {
    vault_id id{};
    std::uint64_t revision = 0;
    secure_bytes content;
};

decoded_payload decode_payload(const secure_bytes& encoded) {
    if (encoded.size() < PAYLOAD_PREFIX) {
        throw vault_format_exception("truncated payload");
    }
    decoded_payload d;
    std::memcpy(d.id.data(), encoded.data(), d.id.size());
    d.revision = get_u64(encoded.data() + 16);
    const std::uint8_t encoding = encoded.data()[24];
    const byte_view body = encoded.view().subview(PAYLOAD_PREFIX);

    if (encoding == ENCODING_RAW) {
        d.content = secure_bytes(body.size);
        if (body.size) std::memcpy(d.content.data(), body.data, body.size);
        return d;
    }
    if (encoding == ENCODING_ZLIB) {
        if (body.size < 8) {
            throw vault_format_exception("truncated compressed payload");
        }
        const std::uint64_t original = get_u64(body.data);
        if (original > vault_container::MAX_CONTENT_SIZE) {
            throw vault_format_exception("declared content size exceeds the limit");
        }
        d.content = secure_bytes(static_cast<std::size_t>(original));
        zlib::decompress_exact(body.subview(8), d.content.data(), d.content.size());
        return d;
    }
    throw vault_format_exception("unknown payload encoding " + std::to_string(encoding));
}

} // namespace

// ---------------------------------------------------------------------------
// vault_header
// ---------------------------------------------------------------------------

std::vector<std::uint8_t> vault_header::serialize() const {
    std::vector<std::uint8_t> h(size(), 0);
    write_stable_prefix(h.data(), type);
    put_u16(h.data() + OFF_FLAGS, 0);
    h[OFF_SLOT_COUNT] = static_cast<std::uint8_t>(slots.size());
    h[OFF_RESERVED] = 0;
    std::memcpy(h.data() + OFF_PAYLOAD_NONCE, payload_nonce.data(), payload_nonce.size());
    for (std::size_t i = 0; i < slots.size(); ++i) {
        write_slot(h.data() + FIXED_SIZE + i * key_slot::SIZE, slots[i]);
    }
    return h;
}

std::vector<std::uint8_t> vault_header::slot_ad(std::size_t index) const {
    return slot_ad_for(type, slots.at(index));
}

const key_slot* vault_header::find(slot_type t) const {
    for (const auto& s : slots) {
        if (s.type == t) return &s;
    }
    return nullptr;
}

vault_header vault_header::parse(byte_view file, content_type expected) {
    if (file.size < FIXED_SIZE) {
        throw vault_format_exception("file too short");
    }
    const std::uint8_t* p = file.data;
    if (std::memcmp(p, MAGIC, sizeof MAGIC) != 0) {
        throw vault_format_exception("not a PhylaxBox file");
    }
    const std::uint16_t version = get_u16(p + OFF_VERSION);
    if (version != VERSION) {
        throw vault_format_exception("unsupported format version " + std::to_string(version),
                                     ErrorCodes::UNSUPPORTED_VERSION);
    }
    if (p[OFF_CONTENT_TYPE] != static_cast<std::uint8_t>(expected)) {
        throw vault_format_exception("unexpected content type", ErrorCodes::WRONG_CONTENT_TYPE);
    }
    if (p[OFF_AEAD_ID] != AEAD_XCHACHA20_POLY1305) {
        throw vault_format_exception("unknown AEAD");
    }
    if (get_u16(p + OFF_FLAGS) != 0 || p[OFF_RESERVED] != 0) {
        throw vault_format_exception("reserved header fields are set");
    }
    const std::size_t slot_count = p[OFF_SLOT_COUNT];
    if (slot_count < 1 || slot_count > MAX_SLOTS) {
        throw vault_format_exception("invalid key slot count");
    }

    vault_header h;
    h.type = expected;
    if (file.size < h.FIXED_SIZE + slot_count * key_slot::SIZE + MIN_PAYLOAD_CIPHERTEXT) {
        throw vault_format_exception("file too short");
    }
    copy_into(h.payload_nonce, file.subview(OFF_PAYLOAD_NONCE, crypto::NONCE_BYTES));

    for (std::size_t i = 0; i < slot_count; ++i) {
        const byte_view sv = file.subview(FIXED_SIZE + i * key_slot::SIZE, key_slot::SIZE);
        const std::uint8_t* s = sv.data;
        key_slot slot;
        if (s[SLOT_RESERVED] != 0 || s[SLOT_RESERVED + 1] != 0 || s[SLOT_RESERVED + 2] != 0) {
            throw vault_format_exception("reserved key slot fields are set");
        }
        slot.kdf.opslimit = get_u32(s + SLOT_OPSLIMIT);
        slot.kdf.memlimit_kib = get_u32(s + SLOT_MEMLIMIT);
        switch (s[SLOT_TYPE]) {
        case static_cast<std::uint8_t>(slot_type::password):
            slot.type = slot_type::password;
            if (!slot.kdf.within_limits()) {
                throw vault_format_exception("KDF parameters out of range");
            }
            break;
        case static_cast<std::uint8_t>(slot_type::recovery_key):
            slot.type = slot_type::recovery_key;
            if (slot.kdf.opslimit != 0 || slot.kdf.memlimit_kib != 0) {
                throw vault_format_exception("recovery slot has KDF parameters");
            }
            break;
        default:
            throw vault_format_exception("unknown key slot type");
        }
        if (h.find(slot.type) != nullptr) {
            throw vault_format_exception("duplicate key slot type");
        }
        copy_into(slot.salt, sv.subview(SLOT_SALT, crypto::SALT_BYTES));
        copy_into(slot.key_nonce, sv.subview(SLOT_KEY_NONCE, crypto::NONCE_BYTES));
        copy_into(slot.wrapped_key, sv.subview(SLOT_WRAPPED_KEY, slot.wrapped_key.size()));
        h.slots.push_back(slot);
    }
    return h;
}

// ---------------------------------------------------------------------------
// vault_container
// ---------------------------------------------------------------------------

struct vault_container_impl {
    using kek_fn = std::function<secure_bytes(const key_slot&)>;

    static vault_container open(byte_view file, content_type expected, slot_type type,
                                const kek_fn& derive, const char* wrong_key_message,
                                secure_bytes& content) {
        vault_header header = vault_header::parse(file, expected);
        const auto it = std::find_if(header.slots.begin(), header.slots.end(),
                                     [&](const key_slot& s) { return s.type == type; });
        if (it == header.slots.end()) {
            if (type == slot_type::recovery_key) {
                throw pbexception(ErrorCodes::NO_RECOVERY_SLOT, "vault has no recovery key");
            }
            throw vault_format_exception("vault has no password slot");
        }
        const std::size_t index = static_cast<std::size_t>(it - header.slots.begin());

        const secure_bytes kek = derive(*it);
        secure_bytes vault_key;
        if (!crypto::aead_decrypt(kek, view_of(it->key_nonce), view_of(it->wrapped_key),
                                  header.slot_ad(index), vault_key) ||
            vault_key.size() != crypto::KEY_BYTES) {
            throw wrong_password_exception(wrong_key_message);
        }

        decoded_payload d = decrypt_payload(header, file, vault_key);
        content = std::move(d.content);
        return vault_container(std::move(header), std::move(vault_key), d.id, d.revision);
    }

    static decoded_payload decrypt_payload(const vault_header& header, byte_view file,
                                           const secure_bytes& vault_key) {
        const std::size_t hsize = header.size();
        secure_bytes encoded;
        if (!crypto::aead_decrypt(vault_key, view_of(header.payload_nonce), file.subview(hsize),
                                  file.subview(0, hsize), encoded)) {
            throw integrity_exception("payload failed authentication (corrupted or tampered file)");
        }
        return decode_payload(encoded);
    }
};

vault_container::vault_container(vault_header header, secure_bytes vault_key, const vault_id& id,
                                 std::uint64_t revision)
    : m_header(std::move(header)), m_vault_key(std::move(vault_key)), m_vault_id(id),
      m_revision(revision) {}

void vault_container::put_slot(key_slot slot, const secure_bytes& kek) {
    const auto wrapped = crypto::aead_encrypt(kek, view_of(slot.key_nonce), m_vault_key,
                                              slot_ad_for(m_header.type, slot));
    copy_into(slot.wrapped_key, wrapped);

    auto it = std::find_if(m_header.slots.begin(), m_header.slots.end(),
                           [&](const key_slot& s) { return s.type == slot.type; });
    if (it != m_header.slots.end()) {
        *it = slot;
    } else {
        if (m_header.slots.size() >= vault_header::MAX_SLOTS) {
            throw std::logic_error("too many key slots");
        }
        m_header.slots.push_back(slot);
    }
}

vault_container vault_container::create(std::string_view password, content_type type,
                                        const crypto::kdf_params& params) {
    const auto salt = random_array<crypto::SALT_BYTES>();
    const auto key_nonce = random_array<crypto::NONCE_BYTES>();
    const auto id = random_array<16>();
    secure_bytes vault_key(crypto::KEY_BYTES);
    crypto::random_bytes(vault_key.data(), vault_key.size());
    return vault_test_access::create(password, type, params, view_of(salt), view_of(key_nonce),
                                     vault_key, view_of(id));
}

vault_container vault_container::open(std::string_view password, byte_view file,
                                      content_type expected, secure_bytes& content) {
    return vault_container_impl::open(
        file, expected, slot_type::password,
        [&](const key_slot& s) { return kek_for_slot(s, password); }, "wrong password", content);
}

vault_container vault_container::open_with_recovery_key(const recovery_key& key, byte_view file,
                                                        content_type expected,
                                                        secure_bytes& content) {
    return vault_container_impl::open(
        file, expected, slot_type::recovery_key,
        [&](const key_slot& s) { return recovery_kek(key, view_of(s.salt)); },
        "wrong recovery key", content);
}

std::uint64_t vault_container::read_version(byte_view file, secure_bytes& content) const {
    const vault_header header = vault_header::parse(file, m_header.type);
    decoded_payload d = vault_container_impl::decrypt_payload(header, file, m_vault_key);
    if (d.id != m_vault_id) {
        throw vault_format_exception("file belongs to a different vault");
    }
    content = std::move(d.content);
    return d.revision;
}

std::uint64_t vault_container::reload(byte_view file, secure_bytes& content) {
    const std::uint64_t revision = read_version(file, content);
    m_header = vault_header::parse(file, m_header.type);
    m_revision = std::max(m_revision, revision);
    return revision;
}

std::vector<std::uint8_t> vault_container::seal(byte_view content, bool compress) {
    const auto nonce = random_array<crypto::NONCE_BYTES>();
    return seal_with_nonce(content, compress, view_of(nonce));
}

std::vector<std::uint8_t> vault_container::seal_with_nonce(byte_view content, bool compress,
                                                           byte_view nonce) {
    if (m_revision == UINT64_MAX) {
        throw std::overflow_error("revision counter exhausted");
    }
    vault_header next = m_header;
    copy_into(next.payload_nonce, nonce);
    const auto ad = next.serialize();
    const std::uint64_t revision = m_revision + 1;
    const secure_bytes encoded = encode_payload(m_vault_id, revision, content, compress);
    const auto ciphertext = crypto::aead_encrypt(m_vault_key, nonce, encoded, ad);

    std::vector<std::uint8_t> file;
    file.reserve(ad.size() + ciphertext.size());
    file.insert(file.end(), ad.begin(), ad.end());
    file.insert(file.end(), ciphertext.begin(), ciphertext.end());
    m_header = std::move(next);
    m_revision = revision;
    return file;
}

void vault_container::change_password(std::string_view new_password,
                                      const crypto::kdf_params& params) {
    key_slot slot;
    slot.type = slot_type::password;
    slot.kdf = params;
    slot.salt = random_array<crypto::SALT_BYTES>();
    slot.key_nonce = random_array<crypto::NONCE_BYTES>();
    put_slot(slot, kek_for_slot(slot, new_password));
}

recovery_key vault_container::add_recovery_key() {
    recovery_key key = recovery_key::generate();
    const auto salt = random_array<crypto::SALT_BYTES>();
    const auto nonce = random_array<crypto::NONCE_BYTES>();
    vault_test_access::add_recovery_key(*this, key, view_of(salt), view_of(nonce));
    return key;
}

void vault_container::remove_recovery_key() {
    if (m_header.find(slot_type::password) == nullptr) {
        throw std::logic_error("cannot remove the recovery key without a password slot");
    }
    auto& slots = m_header.slots;
    slots.erase(std::remove_if(slots.begin(), slots.end(),
                               [](const key_slot& s) { return s.type == slot_type::recovery_key; }),
                slots.end());
}

void vault_container::ensure_revision_above(std::uint64_t revision) {
    m_revision = std::max(m_revision, revision);
}

// ---------------------------------------------------------------------------
// Deterministic hooks (test vectors only)
// ---------------------------------------------------------------------------

vault_container vault_test_access::create(std::string_view password, content_type type,
                                          const crypto::kdf_params& params, byte_view salt,
                                          byte_view key_nonce, byte_view vault_key,
                                          byte_view id_bytes) {
    if (vault_key.size != crypto::KEY_BYTES) {
        throw std::invalid_argument("vault key must be 32 bytes");
    }
    secure_bytes key(crypto::KEY_BYTES);
    std::memcpy(key.data(), vault_key.data, crypto::KEY_BYTES);
    vault_id id{};
    copy_into(id, id_bytes);

    vault_header header;
    header.type = type;
    vault_container c(std::move(header), std::move(key), id, 0);

    key_slot slot;
    slot.type = slot_type::password;
    slot.kdf = params;
    copy_into(slot.salt, salt);
    copy_into(slot.key_nonce, key_nonce);
    c.put_slot(slot, kek_for_slot(slot, password));
    return c;
}

void vault_test_access::add_recovery_key(vault_container& c, const recovery_key& key,
                                         byte_view salt, byte_view key_nonce) {
    key_slot slot;
    slot.type = slot_type::recovery_key;
    copy_into(slot.salt, salt);
    copy_into(slot.key_nonce, key_nonce);
    c.put_slot(slot, recovery_kek(key, view_of(slot.salt)));
}

std::vector<std::uint8_t> vault_test_access::seal(vault_container& c, byte_view content,
                                                  bool compress, byte_view payload_nonce) {
    return c.seal_with_nonce(content, compress, payload_nonce);
}

} // namespace pb
