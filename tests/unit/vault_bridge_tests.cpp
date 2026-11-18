#include "models/pbexceptions.h"
#include "storage/file_io.h"
#include "test_helpers.h"
#include "vault_bridge.h"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <string>

using pb::app::vault_bridge;
using pb::vault_store;
using pb_test::fast_kdf;
using pb_test::temp_dir;
using json = nlohmann::json;

namespace {

const std::string kPassword = "correct horse battery";

// Every reply must be ASCII JSON (it is spliced into JavaScript).
json parse_reply(const std::string& out) {
    for (unsigned char c : out) EXPECT_LT(c, 0x80) << "reply must be ASCII-only: " << out;
    auto js = json::parse(out);
    EXPECT_TRUE(js.contains("ok"));
    EXPECT_TRUE(js.contains("code"));
    EXPECT_TRUE(js.contains("message"));
    return js;
}

std::string args(const json& a) { return a.dump(); }

struct fixture {
    temp_dir dir;
    vault_store store{dir.path() / "vault.phylaxbox", fast_kdf()};
    vault_bridge bridge{store};
};

} // namespace

TEST(VaultBridge, FirstRunStatus) {
    fixture f;
    const auto s = parse_reply(f.bridge.status("[]"));
    EXPECT_EQ(s.at("ok"), true);
    EXPECT_EQ(s.at("exists"), false);
    EXPECT_EQ(s.at("unlocked"), false);
}

TEST(VaultBridge, CreateWithRecoveryKeyThenLockAndUnlock) {
    fixture f;
    const auto created = parse_reply(f.bridge.create(args({kPassword, true})));
    ASSERT_EQ(created.at("ok"), true);
    const std::string key = created.at("recoveryKey");
    EXPECT_EQ(key.size(), 65u); // 55 characters + 10 dashes
    EXPECT_EQ(created.dump().find(kPassword), std::string::npos);

    auto s = parse_reply(f.bridge.status("[]"));
    EXPECT_EQ(s.at("exists"), true);
    EXPECT_EQ(s.at("unlocked"), true);
    EXPECT_EQ(s.at("entries"), 0);
    EXPECT_EQ(s.at("hasRecoveryKey"), true);

    EXPECT_EQ(parse_reply(f.bridge.lock("[]")).at("ok"), true);
    s = parse_reply(f.bridge.status("[]"));
    EXPECT_EQ(s.at("unlocked"), false);
    EXPECT_FALSE(s.contains("entries"));

    const auto unlocked = parse_reply(f.bridge.unlock(args({kPassword})));
    EXPECT_EQ(unlocked.at("ok"), true);
    EXPECT_EQ(unlocked.at("entries"), 0);
}

TEST(VaultBridge, CreateWithoutRecoveryKey) {
    fixture f;
    const auto created = parse_reply(f.bridge.create(args({kPassword, false})));
    EXPECT_EQ(created.at("ok"), true);
    EXPECT_TRUE(created.at("recoveryKey").is_null());
    EXPECT_EQ(parse_reply(f.bridge.status("[]")).at("hasRecoveryKey"), false);
}

TEST(VaultBridge, ErrorsHaveCodesAndMessages) {
    fixture f;
    EXPECT_EQ(parse_reply(f.bridge.create(args({"short", true}))).at("code"), "weak_password");
    EXPECT_EQ(parse_reply(f.bridge.unlock(args({kPassword}))).at("code"), "not_found");

    parse_reply(f.bridge.create(args({kPassword, true})));
    EXPECT_EQ(parse_reply(f.bridge.create(args({kPassword, true}))).at("code"), "vault_exists");
    f.bridge.lock("[]");

    const auto wrong = parse_reply(f.bridge.unlock(args({"not the password"})));
    EXPECT_EQ(wrong.at("ok"), false);
    EXPECT_EQ(wrong.at("code"), "wrong_password");
    EXPECT_FALSE(wrong.at("message").get<std::string>().empty());
    EXPECT_EQ(parse_reply(f.bridge.unlock(args({""}))).at("code"), "empty_password");
}

TEST(VaultBridge, MalformedRequests) {
    fixture f;
    for (const char* request : {"", "nonsense", "{}", "[1]", "[\"pw\", true]"}) {
        EXPECT_EQ(parse_reply(f.bridge.unlock(request)).at("code"), "bad_request") << request;
    }
    EXPECT_EQ(parse_reply(f.bridge.create(args({kPassword, "yes"}))).at("code"), "bad_request");
    EXPECT_EQ(parse_reply(f.bridge.create(args({kPassword}))).at("code"), "bad_request");
    EXPECT_EQ(parse_reply(f.bridge.status("[1]")).at("code"), "bad_request");
    EXPECT_FALSE(f.store.exists()); // nothing was created by a bad request
}

TEST(VaultBridge, RecoverSetsANewPassword) {
    fixture f;
    const std::string key = parse_reply(f.bridge.create(args({kPassword, true}))).at("recoveryKey");
    f.bridge.lock("[]");

    // Lower case and spaces instead of dashes are accepted.
    std::string typed;
    for (char c : key) typed += (c == '-') ? ' ' : static_cast<char>(std::tolower(c));
    const auto recovered = parse_reply(f.bridge.recover(args({typed, "a whole new password"})));
    ASSERT_EQ(recovered.at("ok"), true) << recovered.dump();
    EXPECT_EQ(parse_reply(f.bridge.status("[]")).at("unlocked"), true);

    f.bridge.lock("[]");
    EXPECT_EQ(parse_reply(f.bridge.unlock(args({kPassword}))).at("code"), "wrong_password");
    EXPECT_EQ(parse_reply(f.bridge.unlock(args({"a whole new password"}))).at("ok"), true);
}

TEST(VaultBridge, RecoverErrors) {
    fixture f;
    const std::string key = parse_reply(f.bridge.create(args({kPassword, true}))).at("recoveryKey");
    f.bridge.lock("[]");

    std::string typo = key;
    typo[0] = typo[0] == 'A' ? 'B' : 'A';
    EXPECT_EQ(parse_reply(f.bridge.recover(args({typo, "a whole new password"}))).at("code"),
              "invalid_recovery_key");
    EXPECT_EQ(parse_reply(f.bridge.recover(args({key, "short"}))).at("code"), "weak_password");

    // A valid key of another vault.
    temp_dir other_dir;
    vault_store other(other_dir.path() / "v.phylaxbox", fast_kdf());
    const auto other_key = other.create(kPassword, true);
    EXPECT_EQ(parse_reply(f.bridge.recover(args({other_key->to_text(), "a whole new password"})))
                  .at("code"),
              "wrong_recovery_key");
    EXPECT_EQ(parse_reply(f.bridge.status("[]")).at("unlocked"), false);
}

TEST(VaultBridge, NoRecoveryKeySlot) {
    fixture f;
    parse_reply(f.bridge.create(args({kPassword, false})));
    f.bridge.lock("[]");
    temp_dir other_dir;
    vault_store other(other_dir.path() / "v.phylaxbox", fast_kdf());
    const auto key = other.create(kPassword, true);
    EXPECT_EQ(parse_reply(f.bridge.recover(args({key->to_text(), "a whole new password"})))
                  .at("code"),
              "no_recovery_key");
}

TEST(VaultBridge, CorruptedVault) {
    fixture f;
    parse_reply(f.bridge.create(args({kPassword, false})));
    f.bridge.lock("[]");
    auto bytes = pb::file_io::read_file(f.store.path());
    bytes.back() ^= 1;
    pb::file_io::write_file_atomic(f.store.path(), bytes);
    EXPECT_EQ(parse_reply(f.bridge.unlock(args({kPassword}))).at("code"), "corrupted");

    pb::file_io::write_file_atomic(f.store.path(), std::string_view("not a vault at all, just text"));
    EXPECT_EQ(parse_reply(f.bridge.unlock(args({kPassword}))).at("code"), "invalid_file");
}
