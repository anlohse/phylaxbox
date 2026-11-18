#ifndef PB_SECURE_ALLOCATOR_H_
#define PB_SECURE_ALLOCATOR_H_

#include <nlohmann/json.hpp>
#include <sodium.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace pb {

// Allocator that wipes memory before returning it to the heap, so decrypted
// vault content does not linger in freed blocks (spec §12.2).
//
// Deliberately not sodium_malloc: that maps several pages with guard pages
// per allocation, which does not scale to every string of a 10 000-entry
// vault. Keys and other fixed-size secrets keep using secure_bytes.
//
// `Base` is the allocator that actually provides memory (injectable so tests
// can observe that blocks arrive wiped).
template <typename T, template <typename> class Base = std::allocator>
struct basic_zeroing_allocator {
    using value_type = T;
    template <typename U>
    struct rebind {
        using other = basic_zeroing_allocator<U, Base>;
    };

    basic_zeroing_allocator() noexcept = default;
    template <typename U>
    basic_zeroing_allocator(const basic_zeroing_allocator<U, Base>&) noexcept {}

    T* allocate(std::size_t n) { return Base<T>{}.allocate(n); }

    void deallocate(T* p, std::size_t n) noexcept {
        sodium_memzero(p, n * sizeof(T));
        Base<T>{}.deallocate(p, n);
    }

    template <typename U>
    bool operator==(const basic_zeroing_allocator<U, Base>&) const noexcept { return true; }
    template <typename U>
    bool operator!=(const basic_zeroing_allocator<U, Base>&) const noexcept { return false; }
};

template <typename T>
using zeroing_allocator = basic_zeroing_allocator<T>;

using secure_string = std::basic_string<char, std::char_traits<char>, zeroing_allocator<char>>;

template <typename T>
using secure_vector = std::vector<T, zeroing_allocator<T>>;

// JSON whose strings, arrays and objects are all allocated with
// zeroing_allocator. Used to parse and build the decrypted vault content.
using secure_json = nlohmann::basic_json<std::map, std::vector, secure_string, bool, std::int64_t,
                                         std::uint64_t, double, zeroing_allocator>;

inline secure_string to_secure(std::string_view s) { return secure_string(s.data(), s.size()); }
inline std::string_view view(const secure_string& s) { return std::string_view(s.data(), s.size()); }

} // namespace pb

#endif // PB_SECURE_ALLOCATOR_H_
