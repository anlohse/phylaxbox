#include "models/pbexceptions.h"
#include "test_helpers.h"
#include "vault/recovery_key.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cctype>
#include <regex>

using namespace pb;
using pb_test::counting;
using pb_test::to_hex;

namespace {

int parse_error(const std::string& text) {
    try {
        recovery_key::parse(text);
    } catch (const pbexception& e) {
        return e.errorcode();
    }
    return 0;
}

const recovery_key& fixed_key() {
    static const recovery_key k = recovery_key::from_bytes(counting(0xC0, 32));
    return k;
}

} // namespace

TEST(RecoveryKey, TextShape) {
    const std::string text = recovery_key::generate().to_text();
    // 11 groups of 5 Crockford base32 characters.
    EXPECT_TRUE(std::regex_match(text, std::regex("([0-9A-HJKMNP-TV-Z]{5}-){10}[0-9A-HJKMNP-TV-Z]{5}")))
        << text;
    EXPECT_NE(text, recovery_key::generate().to_text());
}

TEST(RecoveryKey, RoundTrip) {
    for (int i = 0; i < 50; ++i) {
        const auto k = recovery_key::generate();
        EXPECT_EQ(to_hex(recovery_key::parse(k.to_text()).bytes()), to_hex(k.bytes()));
    }
}

TEST(RecoveryKey, LenientInput) {
    const std::string text = fixed_key().to_text();
    std::string lower = text;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    std::string spaced;
    for (char c : text) spaced += (c == '-') ? ' ' : c;
    std::string compact;
    for (char c : text) if (c != '-') compact += c;

    for (const auto& variant : {lower, spaced, compact, "  " + text + "\n"}) {
        EXPECT_EQ(to_hex(recovery_key::parse(variant).bytes()), to_hex(fixed_key().bytes()))
            << variant;
    }
}

TEST(RecoveryKey, AmbiguousLettersAreAccepted) {
    // Crockford: O reads as 0, I and L read as 1.
    const std::string text = fixed_key().to_text();
    std::string confusable = text;
    for (char& c : confusable) {
        if (c == '0') c = 'O';
        else if (c == '1') c = 'l';
    }
    EXPECT_EQ(to_hex(recovery_key::parse(confusable).bytes()), to_hex(fixed_key().bytes()));
}

TEST(RecoveryKey, TyposAreDetected) {
    const std::string text = fixed_key().to_text();
    // Change one character in several positions.
    for (std::size_t pos : {0u, 7u, 20u, 33u, 50u}) {
        std::string typo = text;
        typo[pos] = typo[pos] == 'A' ? 'B' : 'A';
        EXPECT_EQ(parse_error(typo), ErrorCodes::INVALID_RECOVERY_KEY) << "position " << pos;
    }
    // Swap two adjacent characters.
    std::string swapped = text;
    std::size_t i = 0;
    while (swapped[i] == swapped[i + 1] || swapped[i] == '-' || swapped[i + 1] == '-') ++i;
    std::swap(swapped[i], swapped[i + 1]);
    EXPECT_EQ(parse_error(swapped), ErrorCodes::INVALID_RECOVERY_KEY);
}

TEST(RecoveryKey, MalformedInput) {
    const std::string text = fixed_key().to_text();
    EXPECT_EQ(parse_error(""), ErrorCodes::INVALID_RECOVERY_KEY);
    EXPECT_EQ(parse_error(text.substr(0, text.size() - 1)), ErrorCodes::INVALID_RECOVERY_KEY);
    EXPECT_EQ(parse_error(text + "0"), ErrorCodes::INVALID_RECOVERY_KEY);
    std::string with_u = text;
    with_u[0] = 'U'; // not in the Crockford alphabet
    EXPECT_EQ(parse_error(with_u), ErrorCodes::INVALID_RECOVERY_KEY);
    std::string with_symbol = text;
    with_symbol[0] = '#';
    EXPECT_EQ(parse_error(with_symbol), ErrorCodes::INVALID_RECOVERY_KEY);
    // The last character carries 2 data bits; its 3 padding bits must be zero.
    std::string padding = text;
    padding.back() = '1';
    EXPECT_EQ(parse_error(padding), ErrorCodes::INVALID_RECOVERY_KEY);
}

TEST(RecoveryKey, FromBytesRejectsWrongSize) {
    EXPECT_THROW(recovery_key::from_bytes(counting(0, 31)), pbexception);
}
