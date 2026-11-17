#ifndef PB_SECURE_BYTES_H_
#define PB_SECURE_BYTES_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace pb {

// Non-owning, read-only view over a byte range (C++17 stand-in for
// std::span<const std::uint8_t>).
struct byte_view {
    const std::uint8_t* data = nullptr;
    std::size_t size = 0;

    constexpr byte_view() = default;
    constexpr byte_view(const std::uint8_t* d, std::size_t n) : data(d), size(n) {}
    byte_view(const std::vector<std::uint8_t>& v) : data(v.data()), size(v.size()) {}
    byte_view(std::string_view s)
        : data(reinterpret_cast<const std::uint8_t*>(s.data())), size(s.size()) {}
    byte_view(const std::string& s) : byte_view(std::string_view(s)) {}

    bool empty() const { return size == 0; }
    // Throws std::out_of_range when the range does not fit.
    byte_view subview(std::size_t offset, std::size_t count) const;
    byte_view subview(std::size_t offset) const;
};

// Buffer for secrets, allocated with sodium_malloc: guard pages, mlock'ed
// where the OS allows, and wiped on release. Move-only.
class secure_bytes {
public:
    secure_bytes() = default;
    explicit secure_bytes(std::size_t size);
    ~secure_bytes();

    secure_bytes(secure_bytes&& other) noexcept;
    secure_bytes& operator=(secure_bytes&& other) noexcept;
    secure_bytes(const secure_bytes&) = delete;
    secure_bytes& operator=(const secure_bytes&) = delete;

    std::uint8_t* data() { return m_data; }
    const std::uint8_t* data() const { return m_data; }
    std::size_t size() const { return m_size; }
    bool empty() const { return m_size == 0; }

    byte_view view() const { return byte_view(m_data, m_size); }
    operator byte_view() const { return view(); }
    std::string_view as_string_view() const {
        return std::string_view(reinterpret_cast<const char*>(m_data), m_size);
    }

    // Shrinks the logical size (the allocation stays; extra bytes are wiped).
    void truncate(std::size_t new_size);

private:
    void release() noexcept;

    std::uint8_t* m_data = nullptr;
    std::size_t m_size = 0;
};

} // namespace pb

#endif // PB_SECURE_BYTES_H_
