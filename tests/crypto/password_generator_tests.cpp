#include "crypto/password_generator.h"

#include <gtest/gtest.h>

#include <map>
#include <set>
#include <string>

using namespace pb;

namespace {

bool has_any(const secure_string& s, const std::string& set) {
    return s.find_first_of(set) != secure_string::npos;
}

} // namespace

TEST(PasswordGenerator, LengthAndAlphabet) {
    password_options o;
    for (std::size_t len : {password_options::MIN_LENGTH, std::size_t{20}, password_options::MAX_LENGTH}) {
        o.length = len;
        const auto p = generate_password(o);
        EXPECT_EQ(p.size(), len);
        const auto alphabet = password_alphabet(o);
        for (char c : p) EXPECT_NE(alphabet.find(c), std::string::npos) << c;
    }
}

TEST(PasswordGenerator, EverySelectedClassAppears) {
    password_options o;
    o.length = password_options::MIN_LENGTH; // hardest case for the guarantee
    for (int i = 0; i < 500; ++i) {
        const auto p = generate_password(o);
        ASSERT_TRUE(has_any(p, "abcdefghijklmnopqrstuvwxyz")) << p.c_str();
        ASSERT_TRUE(has_any(p, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")) << p.c_str();
        ASSERT_TRUE(has_any(p, "0123456789")) << p.c_str();
        ASSERT_TRUE(has_any(p, "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")) << p.c_str();
    }
}

TEST(PasswordGenerator, SingleClassAndAmbiguousFilter) {
    password_options o;
    o.lowercase = o.uppercase = o.symbols = false;
    o.digits = true;
    o.avoid_ambiguous = true;
    const auto p = generate_password(o);
    for (char c : p) {
        EXPECT_TRUE(c >= '2' && c <= '9') << c; // 0 and 1 excluded
    }
    o.digits = false;
    o.lowercase = o.uppercase = o.symbols = true;
    const auto alphabet = password_alphabet(o);
    for (char c : std::string("0Oo1lI|`'\"")) EXPECT_EQ(alphabet.find(c), std::string::npos) << c;
}

TEST(PasswordGenerator, RejectsBadOptions) {
    password_options o;
    o.length = password_options::MIN_LENGTH - 1;
    EXPECT_THROW(generate_password(o), std::invalid_argument);
    o.length = password_options::MAX_LENGTH + 1;
    EXPECT_THROW(generate_password(o), std::invalid_argument);
    o.length = 20;
    o.lowercase = o.uppercase = o.digits = o.symbols = false;
    EXPECT_THROW(generate_password(o), std::invalid_argument);
}

TEST(PasswordGenerator, OutputLooksUniform) {
    // 4000 passwords of 32 digits: every digit should appear about 12 800
    // times. A loose bound catches gross bias (e.g. modulo bias, a fixed
    // position) without making the test flaky.
    password_options o;
    o.lowercase = o.uppercase = o.symbols = false;
    o.length = 32;
    std::map<char, int> counts;
    std::set<std::string> seen;
    for (int i = 0; i < 4000; ++i) {
        const auto p = generate_password(o);
        for (char c : p) ++counts[c];
        seen.insert(std::string(p.data(), p.size()));
    }
    EXPECT_EQ(seen.size(), 4000u);
    ASSERT_EQ(counts.size(), 10u);
    for (const auto& [digit, n] : counts) {
        EXPECT_GT(n, 11800) << digit;
        EXPECT_LT(n, 13800) << digit;
    }
}
