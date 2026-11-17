#include "crypto/crypto.h"
#include "test_helpers.h"

#include <gtest/gtest.h>

#include <stdexcept>
#include <string>

using namespace pb;
using pb_test::counting;
using pb_test::fast_kdf;

TEST(SecureBytes, AllocatesZeroedAndMoves) {
    secure_bytes a(32);
    ASSERT_EQ(a.size(), 32u);
    for (std::size_t i = 0; i < a.size(); ++i) EXPECT_EQ(a.data()[i], 0);

    a.data()[0] = 0xAB;
    secure_bytes b(std::move(a));
    EXPECT_EQ(b.size(), 32u);
    EXPECT_EQ(b.data()[0], 0xAB);
    EXPECT_TRUE(a.empty()); // NOLINT(bugprone-use-after-move): moved-from state is defined
}

TEST(SecureBytes, ZeroSizeIsEmpty) {
    secure_bytes z(0);
    EXPECT_TRUE(z.empty());
    EXPECT_EQ(z.data(), nullptr);
}

TEST(DeriveKey, IsDeterministic) {
    const auto salt = counting(0, crypto::SALT_BYTES);
    const auto k1 = crypto::derive_key("password", salt, fast_kdf());
    const auto k2 = crypto::derive_key("password", salt, fast_kdf());
    ASSERT_EQ(k1.size(), crypto::KEY_BYTES);
    EXPECT_EQ(pb_test::to_hex(k1), pb_test::to_hex(k2));
}

TEST(DeriveKey, DependsOnPasswordSaltAndParams) {
    const auto salt = counting(0, crypto::SALT_BYTES);
    const auto other_salt = counting(1, crypto::SALT_BYTES);
    const auto base = pb_test::to_hex(crypto::derive_key("password", salt, fast_kdf()));

    EXPECT_NE(base, pb_test::to_hex(crypto::derive_key("Password", salt, fast_kdf())));
    EXPECT_NE(base, pb_test::to_hex(crypto::derive_key("password", other_salt, fast_kdf())));
    EXPECT_NE(base, pb_test::to_hex(crypto::derive_key("password", salt, {2, 64})));
    EXPECT_NE(base, pb_test::to_hex(crypto::derive_key("password", salt, {1, 128})));
}

TEST(DeriveKey, RejectsBadInput) {
    const auto salt = counting(0, crypto::SALT_BYTES);
    const auto short_salt = counting(0, crypto::SALT_BYTES - 1);
    EXPECT_THROW(crypto::derive_key("", salt, fast_kdf()), std::invalid_argument);
    EXPECT_THROW(crypto::derive_key("pw", short_salt, fast_kdf()), std::invalid_argument);
    EXPECT_THROW(crypto::derive_key("pw", salt, {0, 64}), std::invalid_argument);
    EXPECT_THROW(crypto::derive_key("pw", salt, {17, 64}), std::invalid_argument);
    EXPECT_THROW(crypto::derive_key("pw", salt, {1, 4}), std::invalid_argument);
    EXPECT_THROW(crypto::derive_key("pw", salt, {1, 2u * 1024u * 1024u}), std::invalid_argument);
}

TEST(KdfParams, RecommendedIsWithinLimits) {
    EXPECT_TRUE(crypto::kdf_params::recommended().within_limits());
    EXPECT_GE(crypto::kdf_params::recommended().memlimit_kib, 19u * 1024u); // OWASP floor
}

TEST(Aead, RoundTripAndTamperDetection) {
    const auto key = counting(0x40, crypto::KEY_BYTES);
    const auto nonce = counting(0x60, crypto::NONCE_BYTES);
    const std::string msg = "secret message";
    const std::string ad = "header";

    auto ct = crypto::aead_encrypt(key, nonce, msg, ad);
    ASSERT_EQ(ct.size(), msg.size() + crypto::TAG_BYTES);

    secure_bytes pt;
    ASSERT_TRUE(crypto::aead_decrypt(key, nonce, ct, ad, pt));
    EXPECT_EQ(pt.as_string_view(), msg);

    EXPECT_FALSE(crypto::aead_decrypt(key, nonce, ct, std::string_view("other"), pt));
    EXPECT_TRUE(pt.empty());

    ct[0] ^= 1;
    EXPECT_FALSE(crypto::aead_decrypt(key, nonce, ct, ad, pt));

    const std::vector<std::uint8_t> too_short(crypto::TAG_BYTES - 1);
    EXPECT_FALSE(crypto::aead_decrypt(key, nonce, too_short, ad, pt));
}

TEST(Aead, RejectsBadKeyOrNonceSize) {
    const auto key = counting(0, crypto::KEY_BYTES - 1);
    const auto nonce = counting(0, crypto::NONCE_BYTES);
    EXPECT_THROW(crypto::aead_encrypt(key, nonce, std::string_view("x"), byte_view()),
                 std::invalid_argument);
}
