#include "crypto/secure_allocator.h"
#include "models/vault_document.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <memory>
#include <string>

namespace {

// Base allocator that inspects every block when it is returned: counts frees
// and how many still contained non-zero bytes. Lets the test observe the
// wipe without reading freed memory.
struct free_stats {
    std::size_t frees = 0;
    std::size_t dirty_frees = 0;
};
free_stats g_stats;

template <typename T>
struct inspecting_allocator {
    using value_type = T;
    inspecting_allocator() noexcept = default;
    template <typename U>
    inspecting_allocator(const inspecting_allocator<U>&) noexcept {}

    T* allocate(std::size_t n) { return std::allocator<T>{}.allocate(n); }
    void deallocate(T* p, std::size_t n) noexcept {
        const auto* bytes = reinterpret_cast<const unsigned char*>(p);
        ++g_stats.frees;
        if (std::any_of(bytes, bytes + n * sizeof(T), [](unsigned char b) { return b != 0; })) {
            ++g_stats.dirty_frees;
        }
        std::allocator<T>{}.deallocate(p, n);
    }
};

template <typename T>
using test_allocator = pb::basic_zeroing_allocator<T, inspecting_allocator>;
using test_string = std::basic_string<char, std::char_traits<char>, test_allocator<char>>;
using test_json = nlohmann::basic_json<std::map, std::vector, test_string, bool, std::int64_t,
                                       std::uint64_t, double, test_allocator>;

} // namespace

TEST(SecureAllocator, StringBuffersAreWipedBeforeRelease) {
    g_stats = {};
    {
        test_string s(1000, 'x'); // heap allocated (beyond small-string storage)
        s += "more secret text";  // reallocation frees the old buffer
    }
    EXPECT_GE(g_stats.frees, 2u);
    EXPECT_EQ(g_stats.dirty_frees, 0u);
}

TEST(SecureAllocator, ParsedJsonIsWipedBeforeRelease) {
    g_stats = {};
    {
        const auto js = test_json::parse(
            R"({"entries":[{"password":"hunter2-hunter2-hunter2-hunter2","urls":["https://example.com/a/long/path"]}],
                "preferences":{"note":"a string long enough to need its own heap buffer"}})");
        EXPECT_EQ(js["entries"][0]["password"], "hunter2-hunter2-hunter2-hunter2");
        const test_string dumped = js.dump();
        EXPECT_NE(dumped.find("hunter2"), test_string::npos);
    }
    EXPECT_GT(g_stats.frees, 5u); // objects, arrays and strings all went through it
    EXPECT_EQ(g_stats.dirty_frees, 0u);
}

TEST(SecureAllocator, VaultDocumentUsesWipingTypes) {
    // Compile-time guarantee that the secret-bearing fields use the wiping
    // allocator (a refactor back to std::string would fail here).
    static_assert(std::is_same_v<decltype(pb::vault_entry::password), pb::secure_string>);
    static_assert(std::is_same_v<decltype(pb::vault_entry::notes), pb::secure_string>);
    static_assert(std::is_same_v<decltype(pb::vault_entry::username), pb::secure_string>);
    static_assert(std::is_same_v<decltype(pb::vault_entry::urls), pb::secure_vector<pb::secure_string>>);
    static_assert(std::is_same_v<decltype(pb::vault_document::entries), pb::secure_vector<pb::vault_entry>>);
    static_assert(std::is_same_v<decltype(pb::vault_document::preferences), pb::secure_json>);
    static_assert(std::is_same_v<decltype(std::declval<pb::vault_document>().to_json()), pb::secure_string>);
    SUCCEED();
}
