#ifndef PB_TEST_HELPERS_H_
#define PB_TEST_HELPERS_H_

#include "crypto/crypto.h"

#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

namespace pb_test {

inline std::vector<std::uint8_t> from_hex(const std::string& hex) {
    if (hex.size() % 2 != 0) throw std::invalid_argument("odd hex length");
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        throw std::invalid_argument("bad hex digit");
    };
    std::vector<std::uint8_t> out(hex.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::uint8_t>(nibble(hex[2 * i]) << 4 | nibble(hex[2 * i + 1]));
    }
    return out;
}

inline std::string to_hex(pb::byte_view v) {
    static const char* digits = "0123456789abcdef";
    std::string s;
    s.reserve(v.size * 2);
    for (std::size_t i = 0; i < v.size; ++i) {
        s += digits[v.data[i] >> 4];
        s += digits[v.data[i] & 0xF];
    }
    return s;
}

// Bytes start, start+1, ... (used for fixed salts/nonces/keys in vectors).
inline std::vector<std::uint8_t> counting(std::uint8_t start, std::size_t n) {
    std::vector<std::uint8_t> v(n);
    for (std::size_t i = 0; i < n; ++i) v[i] = static_cast<std::uint8_t>(start + i);
    return v;
}

// Cheap parameters so tests stay fast. Never use for real files.
inline pb::crypto::kdf_params fast_kdf() { return pb::crypto::kdf_params{1, 64}; }

// Unique scratch directory removed at scope exit.
class temp_dir {
public:
    temp_dir() {
        std::vector<std::uint8_t> r(8);
        pb::crypto::random_bytes(r.data(), r.size());
        m_path = std::filesystem::temp_directory_path() / ("phylaxbox-test-" + to_hex(r));
        std::filesystem::create_directories(m_path);
    }
    ~temp_dir() {
        std::error_code ec;
        std::filesystem::remove_all(m_path, ec);
    }
    temp_dir(const temp_dir&) = delete;
    temp_dir& operator=(const temp_dir&) = delete;
    const std::filesystem::path& path() const { return m_path; }

private:
    std::filesystem::path m_path;
};

} // namespace pb_test

#endif // PB_TEST_HELPERS_H_
