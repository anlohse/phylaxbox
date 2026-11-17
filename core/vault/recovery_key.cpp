#include "vault/recovery_key.h"

#include "crypto/crypto.h"
#include "models/pbexceptions.h"

#include <sodium.h>

#include <array>
#include <cstring>

namespace pb {

namespace {

constexpr const char* ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // Crockford
constexpr std::size_t CHECK_BYTES = 2;
constexpr std::size_t RAW_BYTES = recovery_key::BYTES + CHECK_BYTES;  // 34
constexpr std::size_t TEXT_CHARS = (RAW_BYTES * 8 + 4) / 5;          // 55
constexpr std::size_t GROUP = 5;

std::array<std::uint8_t, CHECK_BYTES> checksum(byte_view key) {
    std::array<std::uint8_t, crypto_generichash_BYTES> digest{};
    crypto::ensure_initialized();
    crypto_generichash(digest.data(), digest.size(), key.data, key.size, nullptr, 0);
    return {digest[0], digest[1]};
}

int decode_char(char c) {
    if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    if (c == 'O') return 0;
    if (c == 'I' || c == 'L') return 1;
    for (int i = 0; i < 32; ++i) {
        if (ALPHABET[i] == c) return i;
    }
    return -1;
}

[[noreturn]] void invalid(const char* why) {
    throw pbexception(ErrorCodes::INVALID_RECOVERY_KEY, why);
}

} // namespace

recovery_key recovery_key::generate() {
    recovery_key k;
    k.m_key = secure_bytes(BYTES);
    crypto::random_bytes(k.m_key.data(), BYTES);
    return k;
}

recovery_key recovery_key::from_bytes(byte_view bytes) {
    if (bytes.size != BYTES) invalid("recovery key must be 32 bytes");
    recovery_key k;
    k.m_key = secure_bytes(BYTES);
    std::memcpy(k.m_key.data(), bytes.data, BYTES);
    return k;
}

std::string recovery_key::to_text() const {
    secure_bytes raw(RAW_BYTES);
    std::memcpy(raw.data(), m_key.data(), BYTES);
    const auto check = checksum(m_key);
    std::memcpy(raw.data() + BYTES, check.data(), CHECK_BYTES);

    std::string out;
    out.reserve(TEXT_CHARS + TEXT_CHARS / GROUP);
    std::uint32_t buffer = 0;
    int bits = 0;
    std::size_t chars = 0;
    auto emit = [&](unsigned v) {
        if (chars > 0 && chars % GROUP == 0) out += '-';
        out += ALPHABET[v & 31];
        ++chars;
    };
    for (std::size_t i = 0; i < RAW_BYTES; ++i) {
        buffer = (buffer << 8) | raw.data()[i];
        bits += 8;
        while (bits >= 5) {
            emit(buffer >> (bits - 5));
            bits -= 5;
        }
    }
    if (bits > 0) emit(buffer << (5 - bits)); // pad the last 2 bits with zeros
    return out;
}

recovery_key recovery_key::parse(std::string_view text) {
    secure_bytes raw(RAW_BYTES);
    std::size_t out_i = 0;
    std::size_t chars = 0;
    std::uint32_t buffer = 0;
    int bits = 0;
    for (const char c : text) {
        if (c == '-' || c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        const int v = decode_char(c);
        if (v < 0) invalid("recovery key contains an invalid character");
        if (++chars > TEXT_CHARS) invalid("recovery key is too long");
        buffer = (buffer << 5) | static_cast<std::uint32_t>(v);
        bits += 5;
        if (bits >= 8) {
            raw.data()[out_i++] = static_cast<std::uint8_t>(buffer >> (bits - 8));
            bits -= 8;
        }
    }
    if (chars != TEXT_CHARS || out_i != RAW_BYTES) invalid("recovery key is too short");
    if ((buffer & ((1u << bits) - 1u)) != 0) invalid("recovery key is mistyped");

    const auto check = checksum(raw.view().subview(0, BYTES));
    if (sodium_memcmp(check.data(), raw.data() + BYTES, CHECK_BYTES) != 0) {
        invalid("recovery key is mistyped");
    }
    return from_bytes(raw.view().subview(0, BYTES));
}

} // namespace pb
