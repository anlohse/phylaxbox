#include "models/pbexceptions.h"
#include "storage/file_io.h"
#include "test_helpers.h"
#include "vault_bridge.h"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <filesystem>
#include <string>
#include <vector>

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

// Always a JSON array, even with one argument (with nlohmann, `json x = {obj}`
// is the object itself, not a one-element array).
std::string args(std::initializer_list<json> items) {
    json arr = json::array();
    for (const auto& item : items) arr.push_back(item);
    return arr.dump();
}
std::string args(const json& arr) { return arr.dump(); }

const std::string kDevice = "0b6e1c1a-3f5d-4a8e-9c2b-7d4e5f6a7b8c";

struct fixture {
    temp_dir dir;
    vault_store store{dir.path() / "vault.phylaxbox", fast_kdf()};
    std::vector<std::string> clipboard; // what copy() handed to the clipboard
    int locks = 0;
    bool clipboard_works = true;
    vault_bridge bridge{store, kDevice, make_hooks()};

    vault_bridge::hooks make_hooks() {
        vault_bridge::hooks h;
        h.copy_to_clipboard = [this](pb::secure_string&& text) {
            clipboard.emplace_back(text.data(), text.size());
            return clipboard_works;
        };
        h.on_lock = [this] { ++locks; };
        return h;
    }

    // Creates and unlocks a vault.
    void open() { ASSERT_EQ(parse_reply(bridge.create(args({kPassword, false}))).at("ok"), true); }

    std::string add(const json& fields) {
        const auto r = parse_reply(bridge.add(args({fields})));
        EXPECT_EQ(r.at("ok"), true) << r.dump();
        return r.value("id", std::string());
    }
};

json sample_fields() {
    return {{"title", "Example"},
            {"username", "alice"},
            {"password", "hunter2-secret"},
            {"urls", {"https://example.com/login"}},
            {"notes", "first line\nsecond line"},
            {"tags", {"work", "email"}},
            {"favorite", false}};
}

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

// ---------------------------------------------------------------------------
// Entries
// ---------------------------------------------------------------------------

TEST(VaultBridgeEntries, AddListGetRevealUpdateDelete) {
    fixture f;
    f.open();
    const std::string id = f.add(sample_fields());
    ASSERT_FALSE(id.empty());

    // The list never carries passwords or notes.
    const std::string list_out = f.bridge.list("[]");
    EXPECT_EQ(list_out.find("hunter2-secret"), std::string::npos);
    EXPECT_EQ(list_out.find("first line"), std::string::npos);
    const auto list = parse_reply(list_out);
    ASSERT_EQ(list.at("entries").size(), 1u);
    const auto& summary = list.at("entries")[0];
    EXPECT_EQ(summary.at("id"), id);
    EXPECT_EQ(summary.at("title"), "Example");
    EXPECT_EQ(summary.at("username"), "alice");
    EXPECT_EQ(summary.at("tags"), json({"work", "email"}));
    EXPECT_FALSE(summary.contains("password"));

    // Details: notes yes, password only as a flag.
    const std::string get_out = f.bridge.get(args({id}));
    EXPECT_EQ(get_out.find("hunter2-secret"), std::string::npos);
    const auto entry = parse_reply(get_out).at("entry");
    EXPECT_EQ(entry.at("notes"), "first line\nsecond line");
    EXPECT_EQ(entry.at("hasPassword"), true);

    EXPECT_EQ(parse_reply(f.bridge.reveal(args({id}))).at("password"), "hunter2-secret");

    auto changed = sample_fields();
    changed["password"] = "a new secret";
    changed["tags"] = json::array();
    EXPECT_EQ(parse_reply(f.bridge.update(args({id, changed}))).at("ok"), true);
    EXPECT_EQ(parse_reply(f.bridge.reveal(args({id}))).at("password"), "a new secret");
    EXPECT_EQ(f.store.document().entries[0].revision, 2u);
    EXPECT_EQ(f.store.document().entries[0].device_id, kDevice);

    EXPECT_EQ(parse_reply(f.bridge.remove(args({id}))).at("ok"), true);
    EXPECT_TRUE(parse_reply(f.bridge.list("[]")).at("entries").empty());
    EXPECT_EQ(f.store.document().tombstones.size(), 1u);
}

TEST(VaultBridgeEntries, ChangesAreSavedToDisk) {
    fixture f;
    f.open();
    f.add(sample_fields());
    pb::vault_store reopened(f.store.path(), fast_kdf());
    reopened.unlock(kPassword);
    ASSERT_EQ(reopened.document().entries.size(), 1u);
    EXPECT_EQ(reopened.document().entries[0].password, "hunter2-secret");
}

TEST(VaultBridgeEntries, Favorite) {
    fixture f;
    f.open();
    const auto id = f.add(sample_fields());
    EXPECT_EQ(parse_reply(f.bridge.favorite(args({id, true}))).at("ok"), true);
    EXPECT_EQ(parse_reply(f.bridge.list("[]")).at("entries")[0].at("favorite"), true);
    EXPECT_EQ(parse_reply(f.bridge.favorite(args({id, "yes"}))).at("code"), "bad_request");
}

TEST(VaultBridgeEntries, CopyGoesToTheClipboardHookNotTheReply) {
    fixture f;
    f.open();
    const auto id = f.add(sample_fields());
    const std::string out = f.bridge.copy(args({id, "password"}));
    EXPECT_EQ(out.find("hunter2-secret"), std::string::npos);
    const auto reply = parse_reply(out);
    EXPECT_EQ(reply.at("ok"), true);
    EXPECT_EQ(reply.at("clearsIn"), 30);
    EXPECT_EQ(parse_reply(f.bridge.copy(args({id, "username"}))).at("ok"), true);
    EXPECT_EQ(f.clipboard, (std::vector<std::string>{"hunter2-secret", "alice"}));

    EXPECT_EQ(parse_reply(f.bridge.copy(args({id, "notes"}))).at("code"), "bad_request");
    f.clipboard_works = false;
    EXPECT_EQ(parse_reply(f.bridge.copy(args({id, "password"}))).at("code"), "clipboard_error");
}

TEST(VaultBridgeEntries, LockNotifiesAndLaterCallsSayLocked) {
    fixture f;
    f.open();
    const auto id = f.add(sample_fields());
    parse_reply(f.bridge.lock("[]"));
    EXPECT_EQ(f.locks, 1);
    for (const auto& reply : {f.bridge.list("[]"), f.bridge.get(args({id})), f.bridge.reveal(args({id})),
                              f.bridge.copy(args({id, "password"})),
                              f.bridge.add(args({sample_fields()}))}) {
        EXPECT_EQ(parse_reply(reply).at("code"), "locked") << reply;
    }
}

TEST(VaultBridgeEntries, ValidationAndMissingEntries) {
    fixture f;
    f.open();
    auto no_title = sample_fields();
    no_title["title"] = "   ";
    const auto r = parse_reply(f.bridge.add(args({no_title})));
    EXPECT_EQ(r.at("code"), "invalid_entry");
    EXPECT_EQ(r.at("message"), "Informe um título.");
    EXPECT_TRUE(f.store.document().entries.empty());

    auto bad_type = sample_fields();
    bad_type["urls"] = "not a list";
    EXPECT_EQ(parse_reply(f.bridge.add(args({bad_type}))).at("code"), "bad_request");

    const std::string missing = "6f9619ff-8b86-4d01-b42d-00c04fc964ff";
    for (const auto& reply : {f.bridge.get(args({missing})), f.bridge.reveal(args({missing})),
                              f.bridge.update(args({missing, sample_fields()})),
                              f.bridge.remove(args({missing}))}) {
        EXPECT_EQ(parse_reply(reply).at("code"), "entry_not_found") << reply;
    }
}

TEST(VaultBridgeEntries, FailedSaveLeavesTheDocumentUnchanged) {
    fixture f;
    f.open();
    const auto id = f.add(sample_fields());
    // Make the vault file impossible to replace: a directory where the
    // temporary file should be written.
    std::filesystem::create_directory(f.store.path().string() + ".tmp");
    auto changed = sample_fields();
    changed["title"] = "Changed";
    const auto r = parse_reply(f.bridge.update(args({id, changed})));
    EXPECT_EQ(r.at("ok"), false);
    EXPECT_EQ(f.store.document().entries[0].title, "Example"); // rolled back in memory
    EXPECT_EQ(f.store.document().entries[0].revision, 1u);
}

TEST(VaultBridgeTools, GeneratePassword) {
    fixture f; // works while locked: it touches no vault data
    const auto r = parse_reply(f.bridge.generate(
        args({json{{"length", 32}, {"lowercase", true}, {"uppercase", false}, {"digits", true},
                   {"symbols", false}, {"avoidAmbiguous", true}}})));
    ASSERT_EQ(r.at("ok"), true);
    const std::string p = r.at("password");
    EXPECT_EQ(p.size(), 32u);
    for (char c : p) {
        EXPECT_TRUE((c >= 'a' && c <= 'z') || (c >= '2' && c <= '9')) << c;
        EXPECT_NE(c, 'l');
        EXPECT_NE(c, 'o');
    }
    // Built outside the macros: commas inside braces would split macro arguments.
    const json too_short = {{"length", 4}};
    const json no_class = {{"lowercase", false}, {"uppercase", false}, {"digits", false}, {"symbols", false}};
    const json negative = {{"length", -1}};
    for (const json* options : {&too_short, &no_class, &negative}) {
        const std::string request = args(json::array({*options}));
        EXPECT_EQ(parse_reply(f.bridge.generate(request)).at("code"), "bad_options") << request;
    }
}
