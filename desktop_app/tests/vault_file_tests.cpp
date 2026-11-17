#include "pbexceptions.h"
#include "test_helpers.h"
#include "vault_file.h"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <cstring>
#include <fstream>
#include <iostream>
#include <string>

using namespace pb;
using pb_test::counting;
using pb_test::fast_kdf;
using pb_test::from_hex;
using pb_test::to_hex;

namespace {

const std::string kPassword = "correct horse battery staple";

std::vector<std::uint8_t> make_file(const std::string& content, bool compress = true,
                                    content_type type = content_type::vault) {
    auto c = vault_container::create(kPassword, type, fast_kdf());
    return c.seal(content, compress);
}

std::string open_to_string(const std::vector<std::uint8_t>& file,
                           const std::string& password = kPassword,
                           content_type type = content_type::vault) {
    secure_bytes content;
    vault_container::open(password, file, type, content);
    return std::string(content.as_string_view());
}

template <typename E>
int error_code_of(const std::vector<std::uint8_t>& file, content_type type = content_type::vault) {
    try {
        open_to_string(file, kPassword, type);
    } catch (const E& e) {
        return e.errorcode();
    }
    ADD_FAILURE() << "expected exception was not thrown";
    return 0;
}

} // namespace

TEST(VaultFile, RoundTripCompressedAndRaw) {
    const std::string content = R"({"entries":[{"site":"example.com","password":"hunter2"}]})";
    EXPECT_EQ(open_to_string(make_file(content, true)), content);
    EXPECT_EQ(open_to_string(make_file(content, false)), content);
}

TEST(VaultFile, RoundTripEmptyContent) {
    EXPECT_EQ(open_to_string(make_file("", true)), "");
    EXPECT_EQ(open_to_string(make_file("", false)), "");
}

TEST(VaultFile, PlaintextDoesNotAppearInFile) {
    const std::string secret = "hunter2-very-secret-marker";
    for (bool compress : {false, true}) {
        const auto file = make_file(secret, compress);
        const std::string bytes(file.begin(), file.end());
        EXPECT_EQ(bytes.find(secret), std::string::npos);
    }
}

TEST(VaultFile, EachSealUsesAFreshNonce) {
    auto c = vault_container::create(kPassword, content_type::vault, fast_kdf());
    const auto a = c.seal(std::string_view("same"), false);
    const auto b = c.seal(std::string_view("same"), false);
    EXPECT_NE(a, b);
    EXPECT_EQ(open_to_string(a), "same");
    EXPECT_EQ(open_to_string(b), "same");
}

TEST(VaultFile, ResealAfterOpenKeepsKeySlot) {
    const auto file = make_file("v1");
    secure_bytes content;
    auto c = vault_container::open(kPassword, file, content_type::vault, content);
    const auto file2 = c.seal(std::string_view("v2"));
    EXPECT_EQ(open_to_string(file2), "v2");
    // Same salt and wrapped key: no KDF re-run was needed to save.
    EXPECT_TRUE(std::equal(file.begin(), file.begin() + 112, file2.begin()));
}

TEST(VaultFile, WrongPasswordIsReportedAsSuch) {
    const auto file = make_file("data");
    EXPECT_THROW(open_to_string(file, "wrong password"), wrong_password_exception);
}

TEST(VaultFile, TamperedPayloadIsIntegrityError) {
    auto file = make_file("data");
    file.back() ^= 0x01;
    EXPECT_THROW(open_to_string(file), integrity_exception);

    auto file2 = make_file("data");
    file2[112] ^= 0x01; // payload_nonce
    EXPECT_THROW(open_to_string(file2), integrity_exception);
}

TEST(VaultFile, TamperedKeySlotIsWrongPassword) {
    for (std::size_t offset : {24u, 40u, 64u}) { // salt, key_nonce, wrapped_key
        auto file = make_file("data");
        file[offset] ^= 0x01;
        EXPECT_THROW(open_to_string(file), wrong_password_exception) << "offset " << offset;
    }
}

TEST(VaultFile, ContentTypeIsEnforced) {
    const auto file = make_file("data", true, content_type::local_config);
    EXPECT_EQ(error_code_of<vault_format_exception>(file, content_type::vault),
              ErrorCodes::WRONG_CONTENT_TYPE);
    EXPECT_EQ(open_to_string(file, kPassword, content_type::local_config), "data");
}

TEST(VaultFile, MalformedHeadersAreRejectedBeforeKdf) {
    const auto good = make_file("data");

    auto truncated = good;
    truncated.resize(vault_header::SIZE + vault_header::MIN_PAYLOAD_SIZE - 1);
    EXPECT_EQ(error_code_of<vault_format_exception>(truncated), ErrorCodes::INVALID_FORMAT);

    auto bad_magic = good;
    bad_magic[0] = 'X';
    EXPECT_EQ(error_code_of<vault_format_exception>(bad_magic), ErrorCodes::INVALID_FORMAT);

    auto v2 = good;
    v2[8] = 2;
    EXPECT_EQ(error_code_of<vault_format_exception>(v2), ErrorCodes::UNSUPPORTED_VERSION);

    auto flags = good;
    flags[10] = 1;
    EXPECT_EQ(error_code_of<vault_format_exception>(flags), ErrorCodes::INVALID_FORMAT);

    auto reserved = good;
    reserved[15] = 1;
    EXPECT_EQ(error_code_of<vault_format_exception>(reserved), ErrorCodes::INVALID_FORMAT);

    auto kdf = good;
    kdf[12] = 2;
    EXPECT_EQ(error_code_of<vault_format_exception>(kdf), ErrorCodes::INVALID_FORMAT);

    // 4 GiB of Argon2 memory requested by a hostile file: must not be attempted.
    auto huge_mem = good;
    huge_mem[20] = huge_mem[21] = huge_mem[22] = huge_mem[23] = 0xFF;
    EXPECT_EQ(error_code_of<vault_format_exception>(huge_mem), ErrorCodes::INVALID_FORMAT);

    auto huge_ops = good;
    huge_ops[16] = 0xFF;
    EXPECT_EQ(error_code_of<vault_format_exception>(huge_ops), ErrorCodes::INVALID_FORMAT);
}

TEST(VaultFile, ChangePassword) {
    auto c = vault_container::create(kPassword, content_type::vault, fast_kdf());
    const auto old_file = c.seal(std::string_view("data"));
    c.change_password("new password", fast_kdf());
    const auto new_file = c.seal(std::string_view("data"));

    EXPECT_EQ(open_to_string(new_file, "new password"), "data");
    EXPECT_THROW(open_to_string(new_file, kPassword), wrong_password_exception);
    EXPECT_EQ(open_to_string(old_file, kPassword), "data");
}

TEST(VaultFile, CreateRejectsEmptyPassword) {
    EXPECT_THROW(vault_container::create("", content_type::vault, fast_kdf()),
                 std::invalid_argument);
}

// Builds a payload by hand (independently of encode_content) to check the
// decoder's handling of hostile encodings.
namespace {
std::vector<std::uint8_t> file_with_encoded_payload(const std::vector<std::uint8_t>& encoded) {
    const auto salt = counting(0x00, crypto::SALT_BYTES);
    const auto key_nonce = counting(0x10, crypto::NONCE_BYTES);
    const auto vault_key = counting(0x40, crypto::KEY_BYTES);
    const auto payload_nonce = counting(0x60, crypto::NONCE_BYTES);

    auto c = vault_test_access::create(kPassword, content_type::vault, fast_kdf(), salt,
                                       key_nonce, vault_key);
    auto file = vault_test_access::seal(c, std::string_view("x"), false, payload_nonce);
    file.resize(vault_header::SIZE);
    const auto ct = crypto::aead_encrypt(vault_key, payload_nonce, encoded,
                                         byte_view(file.data(), vault_header::SIZE));
    file.insert(file.end(), ct.begin(), ct.end());
    return file;
}
} // namespace

TEST(VaultFile, HostileEncodingsAreRejected) {
    // Unknown encoding.
    EXPECT_THROW(open_to_string(file_with_encoded_payload({7, 'x'})), vault_format_exception);
    // zlib with a truncated length prefix.
    EXPECT_THROW(open_to_string(file_with_encoded_payload({1, 0, 0})), vault_format_exception);
    // Declared size above the 64 MiB limit (decompression bomb).
    EXPECT_THROW(open_to_string(file_with_encoded_payload({1, 0, 0, 0, 0, 1, 0, 0, 0, 0x78})),
                 vault_format_exception);
    // Declared size does not match the stream ("hello" deflated, declared as 4 bytes).
    std::vector<std::uint8_t> wrong_len = {1, 4, 0, 0, 0, 0, 0, 0, 0};
    const auto stream = from_hex("78dacb48cdc9c90700062c0215");
    wrong_len.insert(wrong_len.end(), stream.begin(), stream.end());
    EXPECT_THROW(open_to_string(file_with_encoded_payload(wrong_len)), vault_format_exception);
    // Same stream with the right length decodes.
    wrong_len[1] = 5;
    EXPECT_EQ(open_to_string(file_with_encoded_payload(wrong_len)), "hello");
}

// ---------------------------------------------------------------------------
// Test vectors (docs/test-vectors/vault-v1.json)
// ---------------------------------------------------------------------------

namespace {

struct vector_input {
    std::string name;
    std::string password;
    content_type type;
    crypto::kdf_params kdf;
    std::uint8_t salt_start, key_nonce_start, vault_key_start, payload_nonce_start;
    bool compress;
    std::string plaintext;
};

std::vector<vector_input> vector_inputs() {
    return {
        {"raw-vault", "correct horse battery staple", content_type::vault, {2, 64},
         0x00, 0x10, 0x40, 0x60, false, R"({"entries":[]})"},
        {"raw-config-utf8-password", "p\xC3\xA4ssw\xC3\xB6rd \xE2\x9C\x93", content_type::local_config,
         {2, 64}, 0x01, 0x20, 0x50, 0xA0, false,
         R"({"format":1,"sync_engine":"none","sync_token":""})"},
        {"zlib-vault", "correct horse battery staple", content_type::vault, {2, 64},
         0x02, 0x30, 0x60, 0x80, true,
         R"({"entries":[{"site":"example.com","user":"alice","password":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"site":"example.com","user":"bob","password":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]})"},
    };
}

nlohmann::json build_vector(const vector_input& in) {
    const auto salt = counting(in.salt_start, crypto::SALT_BYTES);
    const auto key_nonce = counting(in.key_nonce_start, crypto::NONCE_BYTES);
    const auto vault_key = counting(in.vault_key_start, crypto::KEY_BYTES);
    const auto payload_nonce = counting(in.payload_nonce_start, crypto::NONCE_BYTES);

    auto c = vault_test_access::create(in.password, in.type, in.kdf, salt, key_nonce, vault_key);
    const auto file = vault_test_access::seal(c, in.plaintext, in.compress, payload_nonce);
    const auto kek = crypto::derive_key(in.password, salt, in.kdf);

    nlohmann::json v;
    v["name"] = in.name;
    v["password_utf8_hex"] = to_hex(byte_view(std::string_view(in.password)));
    v["content_type"] = static_cast<int>(in.type);
    v["kdf_opslimit"] = in.kdf.opslimit;
    v["kdf_memlimit_kib"] = in.kdf.memlimit_kib;
    v["salt_hex"] = to_hex(salt);
    v["key_nonce_hex"] = to_hex(key_nonce);
    v["vault_key_hex"] = to_hex(vault_key);
    v["payload_nonce_hex"] = to_hex(payload_nonce);
    v["encoding"] = in.compress ? "zlib" : "raw";
    v["plaintext"] = in.plaintext;
    v["kek_hex"] = to_hex(kek);
    v["wrapped_key_hex"] = to_hex(byte_view(c.header().wrapped_key.data(), c.header().wrapped_key.size()));
    v["file_hex"] = to_hex(file);
    return v;
}

} // namespace

// Regenerate with:
//   phylaxbox_tests --gtest_also_run_disabled_tests --gtest_filter=*GenerateVectors*
TEST(VaultVectors, DISABLED_GenerateVectors) {
    nlohmann::json doc;
    doc["description"] =
        "PhylaxBox container v1 test vectors (docs/vault-format.md). Salts, nonces and "
        "vault keys are fixed counting sequences. NEVER reuse them in real files.";
    doc["format_version"] = 1;
    doc["vectors"] = nlohmann::json::array();
    for (const auto& in : vector_inputs()) doc["vectors"].push_back(build_vector(in));
    std::cout << doc.dump(2) << std::endl;
}

TEST(VaultVectors, MatchPublishedVectors) {
    std::ifstream f(PB_TEST_VECTORS_FILE);
    ASSERT_TRUE(f) << "cannot open " << PB_TEST_VECTORS_FILE;
    const auto doc = nlohmann::json::parse(f);
    const auto inputs = vector_inputs();
    ASSERT_EQ(doc.at("vectors").size(), inputs.size());

    for (std::size_t i = 0; i < inputs.size(); ++i) {
        const auto& expected = doc["vectors"][i];
        SCOPED_TRACE(expected.at("name").get<std::string>());

        // Every vector must decrypt to its plaintext.
        const auto file = from_hex(expected.at("file_hex").get<std::string>());
        const auto password_bytes = from_hex(expected.at("password_utf8_hex").get<std::string>());
        const std::string password(password_bytes.begin(), password_bytes.end());
        const auto type = static_cast<content_type>(expected.at("content_type").get<int>());
        EXPECT_EQ(open_to_string(file, password, type), expected.at("plaintext").get<std::string>());

        // Raw vectors are fully deterministic: rebuilding must give identical bytes.
        const auto rebuilt = build_vector(inputs[i]);
        EXPECT_EQ(rebuilt.at("kek_hex"), expected.at("kek_hex"));
        EXPECT_EQ(rebuilt.at("wrapped_key_hex"), expected.at("wrapped_key_hex"));
        if (expected.at("encoding") == "raw") {
            EXPECT_EQ(rebuilt.at("file_hex"), expected.at("file_hex"));
        }
    }
}
