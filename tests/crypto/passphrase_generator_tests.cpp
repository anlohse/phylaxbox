#include "crypto/passphrase_generator.h"

#include <gtest/gtest.h>

#include <cmath>
#include <regex>
#include <set>
#include <string>

using namespace pb;

namespace {

std::vector<std::string> split(const std::string& s, const std::string& sep) {
    std::vector<std::string> out;
    std::size_t start = 0;
    for (std::size_t pos; (pos = s.find(sep, start)) != std::string::npos; start = pos + sep.size()) {
        out.push_back(s.substr(start, pos - start));
    }
    out.push_back(s.substr(start));
    return out;
}

bool in_wordlist(const std::string& w) {
    for (std::size_t i = 0; i < passphrase_wordlist_size(); ++i) {
        if (passphrase_word(i) == w) return true;
    }
    return false;
}

} // namespace

TEST(Passphrase, WordlistIsTheEffLongList) {
    EXPECT_EQ(passphrase_wordlist_size(), 7776u);
    EXPECT_EQ(passphrase_word(0), "abacus");      // 11111
    EXPECT_EQ(passphrase_word(7775), "zoom");     // 66666
    EXPECT_THROW(passphrase_word(7776), std::out_of_range);
}

TEST(Passphrase, DefaultShape) {
    const passphrase_options o; // 6 words, "-"
    for (int i = 0; i < 100; ++i) {
        const auto p = generate_passphrase(o);
        const auto words = split(std::string(p.data(), p.size()), "-");
        // Some EFF words contain '-', e.g. "t-shirt"; count words by matching.
        EXPECT_GE(words.size(), 6u);
        EXPECT_TRUE(std::regex_match(std::string(p.data(), p.size()), std::regex("[a-z-]+")));
    }
}

TEST(Passphrase, SeparatorCapitalizeAndNumber) {
    passphrase_options o;
    o.words = 5;
    o.separator = " ";
    o.capitalize = true;
    o.include_number = true;
    for (int i = 0; i < 200; ++i) {
        const auto p = generate_passphrase(o);
        const auto words = split(std::string(p.data(), p.size()), " ");
        ASSERT_EQ(words.size(), 5u) << p.c_str();
        int with_digit = 0;
        for (auto w : words) {
            ASSERT_TRUE(std::isupper(static_cast<unsigned char>(w[0]))) << w;
            if (std::isdigit(static_cast<unsigned char>(w.back()))) {
                ++with_digit;
                w.pop_back();
            }
            w[0] = static_cast<char>(std::tolower(static_cast<unsigned char>(w[0])));
            ASSERT_TRUE(in_wordlist(w)) << w;
        }
        EXPECT_EQ(with_digit, 1) << p.c_str();
    }
}

TEST(Passphrase, Entropy) {
    passphrase_options o;
    EXPECT_NEAR(passphrase_entropy_bits(o), 6 * std::log2(7776.0), 1e-9); // ~77.5
    o.include_number = true;
    EXPECT_NEAR(passphrase_entropy_bits(o), 6 * std::log2(7776.0) + std::log2(10.0) + std::log2(6.0), 1e-9);
}

TEST(Passphrase, RejectsBadOptions) {
    passphrase_options o;
    o.words = 3;
    EXPECT_THROW(generate_passphrase(o), std::invalid_argument);
    o.words = 21;
    EXPECT_THROW(generate_passphrase(o), std::invalid_argument);
    o.words = 6;
    o.separator = "abc";
    EXPECT_THROW(generate_passphrase(o), std::invalid_argument);
    o.separator = "----";
    EXPECT_THROW(generate_passphrase(o), std::invalid_argument);
    o.separator = "";
    EXPECT_NO_THROW(generate_passphrase(o));
}

TEST(Passphrase, WordsAreSpreadOverTheList) {
    // 2000 single-word draws should hit well over 1000 distinct words.
    passphrase_options o;
    o.words = 4;
    o.separator = " ";
    std::set<std::string> seen;
    for (int i = 0; i < 500; ++i) {
        const auto p = generate_passphrase(o);
        for (const auto& w : split(std::string(p.data(), p.size()), " ")) seen.insert(w);
    }
    EXPECT_GT(seen.size(), 1500u);
}
