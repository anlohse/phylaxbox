#include "models/pbexceptions.h"
#include "test_helpers.h"
#include "vault/vault_file.h"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <cstring>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>

using namespace pb;
using pb_test::counting;
using pb_test::fast_kdf;
using pb_test::from_hex;
using pb_test::to_hex;

namespace {

const std::string kPassword = "correct horse battery staple";

// Fixed-header and slot offsets, mirrored from docs/vault-format/README.md so
// the tests check the documented layout rather than the implementation's.
constexpr std::size_t OFF_VERSION = 8, OFF_CONTENT_TYPE = 10, OFF_AEAD = 11, OFF_FLAGS = 12,
                      OFF_SLOT_COUNT = 14, OFF_RESERVED = 15, OFF_PAYLOAD_NONCE = 16,
                      FIXED = 40, SLOT = 100;
constexpr std::size_t S_TYPE = 0, S_RESERVED = 1, S_OPS = 4, S_MEM = 8, S_SALT = 12,
                      S_KEY_NONCE = 28, S_WRAPPED = 52;

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

TEST(VaultFile, LayoutMatchesSpec) {
    const auto file = make_file("x", false);
    ASSERT_GE(file.size(), FIXED + SLOT);
    EXPECT_EQ(std::string(file.begin(), file.begin() + 8), "PHYLAXBX");
    EXPECT_EQ(file[OFF_VERSION], 1);
    EXPECT_EQ(file[OFF_VERSION + 1], 0);
    EXPECT_EQ(file[OFF_CONTENT_TYPE], 1);
    EXPECT_EQ(file[OFF_AEAD], 1);
    EXPECT_EQ(file[OFF_FLAGS], 0);
    EXPECT_EQ(file[OFF_SLOT_COUNT], 1);
    EXPECT_EQ(file[FIXED + S_TYPE], 1); // password slot
    EXPECT_EQ(file[FIXED + S_OPS], fast_kdf().opslimit);
    EXPECT_EQ(file[FIXED + S_MEM], fast_kdf().memlimit_kib);
    // header + payload prefix (25) + 1 byte + tag
    EXPECT_EQ(file.size(), FIXED + SLOT + 25 + 1 + 16);
}

TEST(VaultFile, PlaintextDoesNotAppearInFile) {
    const std::string secret = "hunter2-very-secret-marker";
    for (bool compress : {false, true}) {
        const auto file = make_file(secret, compress);
        const std::string bytes(file.begin(), file.end());
        EXPECT_EQ(bytes.find(secret), std::string::npos);
    }
}

TEST(VaultFile, EachSealUsesAFreshNonceAndRevision) {
    auto c = vault_container::create(kPassword, content_type::vault, fast_kdf());
    EXPECT_EQ(c.revision(), 0u);
    const auto a = c.seal(std::string_view("same"), false);
    EXPECT_EQ(c.revision(), 1u);
    const auto b = c.seal(std::string_view("same"), false);
    EXPECT_EQ(c.revision(), 2u);
    EXPECT_NE(a, b);
    EXPECT_NE(std::vector<std::uint8_t>(a.begin() + OFF_PAYLOAD_NONCE, a.begin() + FIXED),
              std::vector<std::uint8_t>(b.begin() + OFF_PAYLOAD_NONCE, b.begin() + FIXED));

    secure_bytes content;
    EXPECT_EQ(vault_container::open(kPassword, a, content_type::vault, content).revision(), 1u);
    EXPECT_EQ(vault_container::open(kPassword, b, content_type::vault, content).revision(), 2u);
}

TEST(VaultFile, VaultIdIsStableAcrossSavesAndPasswordChanges) {
    auto c = vault_container::create(kPassword, content_type::vault, fast_kdf());
    const auto id = c.id();
    auto other = vault_container::create(kPassword, content_type::vault, fast_kdf());
    EXPECT_NE(id, other.id());

    c.seal(std::string_view("1"));
    c.change_password("new", fast_kdf());
    const auto file = c.seal(std::string_view("2"));
    secure_bytes content;
    EXPECT_EQ(vault_container::open("new", file, content_type::vault, content).id(), id);
}

TEST(VaultFile, ResealAfterOpenContinuesRevisionAndKeepsSlots) {
    const auto file = make_file("v1");
    secure_bytes content;
    auto c = vault_container::open(kPassword, file, content_type::vault, content);
    const auto file2 = c.seal(std::string_view("v2"));
    EXPECT_EQ(c.revision(), 2u);
    EXPECT_EQ(open_to_string(file2), "v2");
    // Same key slot: saving did not need the password again.
    EXPECT_TRUE(std::equal(file.begin() + FIXED, file.begin() + FIXED + SLOT, file2.begin() + FIXED));
}

TEST(VaultFile, EnsureRevisionAbove) {
    auto c = vault_container::create(kPassword, content_type::vault, fast_kdf());
    c.ensure_revision_above(41);
    c.seal(std::string_view("x"));
    EXPECT_EQ(c.revision(), 42u);
    c.ensure_revision_above(10); // never goes backwards
    c.seal(std::string_view("x"));
    EXPECT_EQ(c.revision(), 43u);
}

TEST(VaultFile, WrongPasswordIsReportedAsSuch) {
    const auto file = make_file("data");
    EXPECT_THROW(open_to_string(file, "wrong password"), wrong_password_exception);
}

TEST(VaultFile, TamperedPayloadOrFixedHeaderIsIntegrityError) {
    for (std::size_t offset : {std::size_t{OFF_PAYLOAD_NONCE}, FIXED + SLOT + 3}) {
        auto file = make_file("data");
        file[offset] ^= 0x01;
        EXPECT_THROW(open_to_string(file), integrity_exception) << "offset " << offset;
    }
    auto file = make_file("data");
    file.back() ^= 0x01;
    EXPECT_THROW(open_to_string(file), integrity_exception);
}

TEST(VaultFile, TamperedKeySlotIsWrongPassword) {
    for (std::size_t offset : {S_SALT, S_KEY_NONCE, S_WRAPPED, S_WRAPPED + 47}) {
        auto file = make_file("data");
        file[FIXED + offset] ^= 0x01;
        EXPECT_THROW(open_to_string(file), wrong_password_exception) << "slot offset " << offset;
    }
    // Downgrading the KDF cost changes the KEK: also rejected.
    auto file = make_file("data");
    file[FIXED + S_OPS] = 2;
    EXPECT_THROW(open_to_string(file), wrong_password_exception);
}

TEST(VaultFile, ContentTypeIsEnforced) {
    const auto file = make_file("data", true, content_type::local_config);
    EXPECT_EQ(error_code_of<vault_format_exception>(file, content_type::vault),
              ErrorCodes::WRONG_CONTENT_TYPE);
    EXPECT_EQ(open_to_string(file, kPassword, content_type::local_config), "data");
}

TEST(VaultFile, MalformedHeadersAreRejectedBeforeKdf) {
    const auto good = make_file("data");
    auto expect_format = [&](std::vector<std::uint8_t> f, int code = ErrorCodes::INVALID_FORMAT) {
        EXPECT_EQ(error_code_of<vault_format_exception>(f), code);
    };

    auto truncated = good;
    truncated.resize(FIXED + SLOT + 25 + 16 - 1);
    expect_format(truncated);

    auto bad_magic = good;
    bad_magic[0] = 'X';
    expect_format(bad_magic);

    auto v2 = good;
    v2[OFF_VERSION] = 2;
    expect_format(v2, ErrorCodes::UNSUPPORTED_VERSION);

    auto aead = good;
    aead[OFF_AEAD] = 2;
    expect_format(aead);

    auto flags = good;
    flags[OFF_FLAGS] = 1;
    expect_format(flags);

    auto reserved = good;
    reserved[OFF_RESERVED] = 1;
    expect_format(reserved);

    auto no_slots = good;
    no_slots[OFF_SLOT_COUNT] = 0;
    expect_format(no_slots);

    auto many_slots = good;
    many_slots[OFF_SLOT_COUNT] = 5;
    expect_format(many_slots);

    auto missing_slot_bytes = good;
    missing_slot_bytes[OFF_SLOT_COUNT] = 2; // claims a second slot that is not there
    missing_slot_bytes.resize(FIXED + 2 * SLOT);
    expect_format(missing_slot_bytes);

    auto slot_type = good;
    slot_type[FIXED + S_TYPE] = 9;
    expect_format(slot_type);

    auto slot_reserved = good;
    slot_reserved[FIXED + S_RESERVED + 2] = 1;
    expect_format(slot_reserved);

    // 4 GiB of Argon2 memory requested by a hostile file: must not be attempted.
    auto huge_mem = good;
    for (int i = 0; i < 4; ++i) huge_mem[FIXED + S_MEM + i] = 0xFF;
    expect_format(huge_mem);

    auto huge_ops = good;
    huge_ops[FIXED + S_OPS] = 0xFF;
    expect_format(huge_ops);
}

TEST(VaultFile, DuplicateSlotTypesAreRejected) {
    auto c = vault_container::create(kPassword, content_type::vault, fast_kdf());
    c.add_recovery_key();
    auto file = c.seal(std::string_view("x"));
    ASSERT_EQ(file[OFF_SLOT_COUNT], 2);
    file[FIXED + SLOT + S_TYPE] = 1; // recovery slot relabelled as a second password slot
    EXPECT_EQ(error_code_of<vault_format_exception>(file), ErrorCodes::INVALID_FORMAT);
}

TEST(VaultFile, ChangePassword) {
    auto c = vault_container::create(kPassword, content_type::vault, fast_kdf());
    const auto old_file = c.seal(std::string_view("data"));
    c.change_password("new password", fast_kdf());
    const auto new_file = c.seal(std::string_view("data"));

    EXPECT_EQ(open_to_string(new_file, "new password"), "data");
    EXPECT_THROW(open_to_string(new_file, kPassword), wrong_password_exception);
    EXPECT_EQ(open_to_string(old_file, kPassword), "data");
    EXPECT_EQ(new_file[OFF_SLOT_COUNT], 1); // replaced, not appended
}

TEST(VaultFile, CreateRejectsEmptyPassword) {
    EXPECT_THROW(vault_container::create("", content_type::vault, fast_kdf()),
                 std::invalid_argument);
}

// ---------------------------------------------------------------------------
// Recovery key slot
// ---------------------------------------------------------------------------

TEST(VaultRecovery, UnlockWithRecoveryKeyThenSetNewPassword) {
    auto c = vault_container::create(kPassword, content_type::vault, fast_kdf());
    const recovery_key rk = c.add_recovery_key();
    EXPECT_TRUE(c.has_recovery_key());
    const auto file = c.seal(std::string_view("secrets"));
    EXPECT_EQ(file[OFF_SLOT_COUNT], 2);

    // The user forgot the password: unlock with the printed recovery key.
    secure_bytes content;
    auto recovered = vault_container::open_with_recovery_key(recovery_key::parse(rk.to_text()),
                                                            file, content_type::vault, content);
    EXPECT_EQ(content.as_string_view(), "secrets");
    EXPECT_EQ(recovered.id(), c.id());

    recovered.change_password("brand new", fast_kdf());
    const auto file2 = recovered.seal(std::string_view("secrets"));
    EXPECT_EQ(open_to_string(file2, "brand new"), "secrets");
    EXPECT_THROW(open_to_string(file2, kPassword), wrong_password_exception);
    // The recovery key keeps working after the password change.
    EXPECT_NO_THROW(vault_container::open_with_recovery_key(rk, file2, content_type::vault, content));
}

TEST(VaultRecovery, WrongRecoveryKey) {
    auto c = vault_container::create(kPassword, content_type::vault, fast_kdf());
    c.add_recovery_key();
    const auto file = c.seal(std::string_view("x"));
    secure_bytes content;
    EXPECT_THROW(vault_container::open_with_recovery_key(recovery_key::generate(), file,
                                                         content_type::vault, content),
                 wrong_password_exception);
}

TEST(VaultRecovery, NoRecoverySlot) {
    const auto file = make_file("x");
    secure_bytes content;
    try {
        vault_container::open_with_recovery_key(recovery_key::generate(), file,
                                                content_type::vault, content);
        FAIL() << "expected exception";
    } catch (const pbexception& e) {
        EXPECT_EQ(e.errorcode(), ErrorCodes::NO_RECOVERY_SLOT);
    }
}

TEST(VaultRecovery, AddingRecoveryLaterNeedsNoPasswordAndKeepsPasswordSlot) {
    const auto file = make_file("x");
    secure_bytes content;
    auto c = vault_container::open(kPassword, file, content_type::vault, content);
    const auto rk = c.add_recovery_key();
    const auto file2 = c.seal(std::string_view("y"));
    // The password slot was not re-wrapped (slot AD excludes the slot count).
    EXPECT_TRUE(std::equal(file.begin() + FIXED, file.begin() + FIXED + SLOT, file2.begin() + FIXED));
    EXPECT_EQ(open_to_string(file2), "y");
    EXPECT_NO_THROW(vault_container::open_with_recovery_key(rk, file2, content_type::vault, content));
}

TEST(VaultRecovery, ReplaceAndRemove) {
    auto c = vault_container::create(kPassword, content_type::vault, fast_kdf());
    const auto first = c.add_recovery_key();
    const auto second = c.add_recovery_key();
    auto file = c.seal(std::string_view("x"));
    EXPECT_EQ(file[OFF_SLOT_COUNT], 2);
    secure_bytes content;
    EXPECT_THROW(vault_container::open_with_recovery_key(first, file, content_type::vault, content),
                 wrong_password_exception);
    EXPECT_NO_THROW(
        vault_container::open_with_recovery_key(second, file, content_type::vault, content));

    c.remove_recovery_key();
    EXPECT_FALSE(c.has_recovery_key());
    file = c.seal(std::string_view("x"));
    EXPECT_EQ(file[OFF_SLOT_COUNT], 1);
    EXPECT_EQ(open_to_string(file), "x");
}

// ---------------------------------------------------------------------------
// reload(): reading another version of the same vault with the key in memory
// ---------------------------------------------------------------------------

TEST(VaultReload, AdoptsRemotePasswordChange) {
    // Device A and B share the vault; A changes the password and saves.
    auto a = vault_container::create(kPassword, content_type::vault, fast_kdf());
    const auto v1 = a.seal(std::string_view("v1"));
    secure_bytes content;
    auto b = vault_container::open(kPassword, v1, content_type::vault, content);

    a.change_password("changed on A", fast_kdf());
    const auto v2 = a.seal(std::string_view("v2"));

    // B, still unlocked with the old password, can read and continue.
    EXPECT_EQ(b.reload(v2, content), 2u);
    EXPECT_EQ(content.as_string_view(), "v2");
    const auto v3 = b.seal(std::string_view("v3"));
    EXPECT_EQ(b.revision(), 3u);
    EXPECT_EQ(open_to_string(v3, "changed on A"), "v3");
    EXPECT_THROW(open_to_string(v3, kPassword), wrong_password_exception);
}

TEST(VaultReload, ReportsRollback) {
    auto c = vault_container::create(kPassword, content_type::vault, fast_kdf());
    const auto old_version = c.seal(std::string_view("old"));
    c.seal(std::string_view("new"));
    ASSERT_EQ(c.revision(), 2u);
    secure_bytes content;
    // An attacker with cloud access restores the older, validly encrypted file.
    EXPECT_EQ(c.reload(old_version, content), 1u); // caller sees 1 < 2
    EXPECT_EQ(c.revision(), 2u);                    // and the counter does not go back
}

TEST(VaultReload, RejectsOtherVaults) {
    auto c = vault_container::create(kPassword, content_type::vault, fast_kdf());
    c.seal(std::string_view("x"));
    const auto other = make_file("y");
    secure_bytes content;
    EXPECT_THROW(c.reload(other, content), integrity_exception);
}

// Builds a payload by hand (independently of the encoder) to check the
// decoder's handling of hostile encodings.
namespace {
std::vector<std::uint8_t> file_with_encoded_payload(std::vector<std::uint8_t> body,
                                                    std::uint8_t encoding) {
    const auto vault_key = counting(0x40, crypto::KEY_BYTES);
    const auto vault_id = counting(0x90, 16);
    const auto payload_nonce = counting(0x60, crypto::NONCE_BYTES);
    auto c = vault_test_access::create(kPassword, content_type::vault, fast_kdf(),
                                       counting(0x00, crypto::SALT_BYTES),
                                       counting(0x10, crypto::NONCE_BYTES), vault_key, vault_id);
    auto file = vault_test_access::seal(c, std::string_view("x"), false, payload_nonce);
    file.resize(FIXED + SLOT);

    std::vector<std::uint8_t> encoded(vault_id);
    for (int i = 0; i < 8; ++i) encoded.push_back(i == 0 ? 1 : 0); // revision 1
    encoded.push_back(encoding);
    encoded.insert(encoded.end(), body.begin(), body.end());

    const auto ct = crypto::aead_encrypt(vault_key, payload_nonce, encoded,
                                         byte_view(file.data(), file.size()));
    file.insert(file.end(), ct.begin(), ct.end());
    return file;
}
} // namespace

TEST(VaultFile, HostileEncodingsAreRejected) {
    EXPECT_THROW(open_to_string(file_with_encoded_payload({'x'}, 7)), vault_format_exception);
    EXPECT_THROW(open_to_string(file_with_encoded_payload({0, 0, 0}, 1)), vault_format_exception);
    // Declared size above the 64 MiB limit (decompression bomb).
    EXPECT_THROW(open_to_string(file_with_encoded_payload({0, 0, 0, 0, 1, 0, 0, 0, 0x78}, 1)),
                 vault_format_exception);
    // zlib("hello") declared as 4 bytes, then correctly as 5.
    const auto stream = from_hex("78dacb48cdc9c90700062c0215");
    std::vector<std::uint8_t> body = {4, 0, 0, 0, 0, 0, 0, 0};
    body.insert(body.end(), stream.begin(), stream.end());
    EXPECT_THROW(open_to_string(file_with_encoded_payload(body, 1)), vault_format_exception);
    body[0] = 5;
    EXPECT_EQ(open_to_string(file_with_encoded_payload(body, 1)), "hello");
}

// ---------------------------------------------------------------------------
// Test vectors (docs/vault-format/test-vectors/vault-v1.json)
// ---------------------------------------------------------------------------

namespace {

struct recovery_input {
    std::uint8_t key_start, salt_start, key_nonce_start;
};

struct vector_input {
    std::string name;
    std::string password;
    content_type type;
    crypto::kdf_params kdf;
    std::uint8_t salt_start, key_nonce_start, vault_key_start, vault_id_start, payload_nonce_start;
    std::optional<recovery_input> recovery;
    bool compress;
    std::string plaintext;
};

std::vector<vector_input> vector_inputs() {
    return {
        {"password-raw", "correct horse battery staple", content_type::vault, {2, 64},
         0x00, 0x10, 0x40, 0x90, 0x60, std::nullopt, false,
         R"({"schema":1,"entries":[],"tombstones":[],"preferences":{}})"},
        {"password-and-recovery-raw", "p\xC3\xA4ssw\xC3\xB6rd \xE2\x9C\x93", content_type::vault,
         {2, 64}, 0x01, 0x20, 0x50, 0xA0, 0xB0, recovery_input{0xC0, 0x05, 0x30}, false,
         R"({"schema":1,"entries":[{"id":"6f9619ff-8b86-4d01-b42d-00c04fc964ff","title":"Example","username":"alice","password":"hunter2","urls":["https://example.com"],"application":"","notes":"","tags":[],"favorite":false,"createdAt":"2026-11-17T12:00:00.000Z","updatedAt":"2026-11-17T12:00:00.000Z","revision":1,"deviceId":"0b6e1c1a-3f5d-4a8e-9c2b-7d4e5f6a7b8c"}],"tombstones":[],"preferences":{}})"},
        {"config-raw", "correct horse battery staple", content_type::local_config, {2, 64},
         0x02, 0x30, 0x60, 0xD0, 0x70, std::nullopt, false,
         R"({"format":1,"sync_engine":"none","sync_token":""})"},
        {"password-zlib", "correct horse battery staple", content_type::vault, {2, 64},
         0x03, 0x40, 0x70, 0xE0, 0x80, std::nullopt, true,
         R"({"schema":1,"entries":[],"tombstones":[],"preferences":{"note":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}})"},
    };
}

nlohmann::json build_vector(const vector_input& in) {
    const auto salt = counting(in.salt_start, crypto::SALT_BYTES);
    const auto key_nonce = counting(in.key_nonce_start, crypto::NONCE_BYTES);
    const auto vault_key = counting(in.vault_key_start, crypto::KEY_BYTES);
    const auto vault_id = counting(in.vault_id_start, 16);
    const auto payload_nonce = counting(in.payload_nonce_start, crypto::NONCE_BYTES);

    auto c = vault_test_access::create(in.password, in.type, in.kdf, salt, key_nonce, vault_key,
                                       vault_id);
    nlohmann::json v;
    if (in.recovery) {
        const auto rk = recovery_key::from_bytes(counting(in.recovery->key_start, 32));
        const auto rsalt = counting(in.recovery->salt_start, crypto::SALT_BYTES);
        const auto rnonce = counting(in.recovery->key_nonce_start, crypto::NONCE_BYTES);
        vault_test_access::add_recovery_key(c, rk, rsalt, rnonce);
        const auto* slot = c.header().find(slot_type::recovery_key);
        v["recovery"] = {{"key_hex", to_hex(rk.bytes())},
                         {"key_text", rk.to_text()},
                         {"salt_hex", to_hex(rsalt)},
                         {"key_nonce_hex", to_hex(rnonce)},
                         {"wrapped_key_hex", to_hex(byte_view(slot->wrapped_key.data(),
                                                              slot->wrapped_key.size()))}};
    }
    const auto file = vault_test_access::seal(c, in.plaintext, in.compress, payload_nonce);
    const auto kek = crypto::derive_key(in.password, salt, in.kdf);
    const auto* pw = c.header().find(slot_type::password);

    v["name"] = in.name;
    v["password_utf8_hex"] = to_hex(byte_view(std::string_view(in.password)));
    v["content_type"] = static_cast<int>(in.type);
    v["kdf_opslimit"] = in.kdf.opslimit;
    v["kdf_memlimit_kib"] = in.kdf.memlimit_kib;
    v["salt_hex"] = to_hex(salt);
    v["key_nonce_hex"] = to_hex(key_nonce);
    v["vault_key_hex"] = to_hex(vault_key);
    v["vault_id_hex"] = to_hex(vault_id);
    v["revision"] = c.revision();
    v["payload_nonce_hex"] = to_hex(payload_nonce);
    v["encoding"] = in.compress ? "zlib" : "raw";
    v["plaintext"] = in.plaintext;
    v["kek_hex"] = to_hex(kek);
    v["wrapped_key_hex"] = to_hex(byte_view(pw->wrapped_key.data(), pw->wrapped_key.size()));
    v["file_hex"] = to_hex(file);
    return v;
}

} // namespace

// Regenerate with:
//   phylaxbox_core_tests --gtest_also_run_disabled_tests --gtest_filter=*GenerateVectors*
TEST(VaultVectors, DISABLED_GenerateVectors) {
    nlohmann::json doc;
    doc["description"] =
        "PhylaxBox container v1 test vectors (docs/vault-format/README.md). Salts, nonces, "
        "vault keys, vault ids and recovery keys are fixed counting sequences. NEVER reuse them "
        "in real files.";
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

        const auto file = from_hex(expected.at("file_hex").get<std::string>());
        const auto password_bytes = from_hex(expected.at("password_utf8_hex").get<std::string>());
        const std::string password(password_bytes.begin(), password_bytes.end());
        const auto type = static_cast<content_type>(expected.at("content_type").get<int>());

        // Every vector must decrypt to its plaintext, id and revision.
        secure_bytes content;
        const auto opened = vault_container::open(password, file, type, content);
        EXPECT_EQ(content.as_string_view(), expected.at("plaintext").get<std::string>());
        EXPECT_EQ(to_hex(byte_view(opened.id().data(), opened.id().size())),
                  expected.at("vault_id_hex").get<std::string>());
        EXPECT_EQ(opened.revision(), expected.at("revision").get<std::uint64_t>());

        if (expected.contains("recovery")) {
            const auto rk = recovery_key::parse(expected["recovery"].at("key_text").get<std::string>());
            EXPECT_EQ(to_hex(rk.bytes()), expected["recovery"].at("key_hex").get<std::string>());
            vault_container::open_with_recovery_key(rk, file, type, content);
            EXPECT_EQ(content.as_string_view(), expected.at("plaintext").get<std::string>());
        }

        // Raw vectors are fully deterministic: rebuilding must give identical bytes.
        const auto rebuilt = build_vector(inputs[i]);
        EXPECT_EQ(rebuilt.at("kek_hex"), expected.at("kek_hex"));
        EXPECT_EQ(rebuilt.at("wrapped_key_hex"), expected.at("wrapped_key_hex"));
        if (expected.at("encoding") == "raw") {
            EXPECT_EQ(rebuilt.at("file_hex"), expected.at("file_hex"));
        }
    }
}
