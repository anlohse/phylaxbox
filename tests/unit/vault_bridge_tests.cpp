#include "models/pbexceptions.h"
#include "models/vault_preferences.h"
#include "storage/file_io.h"
#include "test_helpers.h"
#include "vault_bridge.h"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <optional>
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
    std::filesystem::path settings_file = dir.path() / "settings.json";
    std::vector<std::string> clipboard; // what copy() handed to the clipboard
    std::vector<std::chrono::seconds> clear_after;
    int locks = 0;
    bool clipboard_works = true;
    std::optional<std::string> dialog_answer; // what the "file dialog" returns
    std::vector<pb::app::file_dialog_request> dialogs;
    vault_bridge bridge{store, kDevice, settings_file, make_hooks()};

    vault_bridge::hooks make_hooks() {
        vault_bridge::hooks h;
        h.copy_to_clipboard = [this](pb::secure_string&& text, std::chrono::seconds after) {
            clipboard.emplace_back(text.data(), text.size());
            clear_after.push_back(after);
            return clipboard_works;
        };
        h.on_lock = [this] { ++locks; };
        h.choose_file = [this](const pb::app::file_dialog_request& request) {
            dialogs.push_back(request);
            return dialog_answer;
        };
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
    EXPECT_EQ(s.at("isDefaultPath"), false);
    EXPECT_FALSE(s.at("vaultPath").get<std::string>().empty());
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
    EXPECT_EQ(f.clear_after[0], std::chrono::seconds(30));

    // The clearing time comes from the vault preferences.
    const json prefs = {{"clipboardClearSeconds", 12}};
    ASSERT_EQ(parse_reply(f.bridge.settings_set_vault(args({prefs}))).at("ok"), true);
    EXPECT_EQ(parse_reply(f.bridge.copy(args({id, "password"}))).at("clearsIn"), 12);
    EXPECT_EQ(f.clear_after.back(), std::chrono::seconds(12));

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
    EXPECT_EQ(r.at("code"), "title_required");
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

TEST(VaultBridgeTools, GeneratePassphrase) {
    fixture f;
    const json options = {{"words", 5}, {"separator", "."}, {"capitalize", true}, {"includeNumber", false}};
    const auto r = parse_reply(f.bridge.generate_passphrase(args({options})));
    ASSERT_EQ(r.at("ok"), true) << r.dump();
    const std::string p = r.at("password");
    EXPECT_EQ(std::count(p.begin(), p.end(), '.'), 4);
    EXPECT_TRUE(p[0] >= 'A' && p[0] <= 'Z') << p;
    EXPECT_NEAR(r.at("bits").get<double>(), 5 * std::log2(7776.0), 0.01);

    const json too_few = {{"words", 2}};
    const json letters = {{"separator", "x"}};
    for (const json* bad : {&too_few, &letters}) {
        const std::string request = args(json::array({*bad}));
        EXPECT_EQ(parse_reply(f.bridge.generate_passphrase(request)).at("code"), "bad_options") << request;
    }
    EXPECT_EQ(parse_reply(f.bridge.app_info("[]")).at("wordlistSize"), 7776);
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

TEST(VaultBridgeSettings, DeviceSettingsArePersisted) {
    fixture f;
    auto s = parse_reply(f.bridge.settings_get("[]"));
    EXPECT_EQ(s.at("device").at("theme"), "system");
    EXPECT_EQ(s.at("device").at("backupRetention"), 10);
    EXPECT_FALSE(s.contains("vault")); // locked: the vault preferences are not readable

    const json changes = {{"theme", "dark"}, {"language", "en"}, {"backupRetention", 3}};
    ASSERT_EQ(parse_reply(f.bridge.settings_set_device(args({changes}))).at("ok"), true);
    EXPECT_EQ(f.store.backup_retention(), 3u);

    vault_bridge again{f.store, kDevice, f.settings_file};
    s = parse_reply(again.settings_get("[]"));
    EXPECT_EQ(s.at("device").at("theme"), "dark");
    EXPECT_EQ(s.at("device").at("language"), "en");
    EXPECT_EQ(s.at("device").at("backupRetention"), 3);

    const json bad_theme = {{"theme", "neon"}};
    const json bad_retention = {{"backupRetention", 0}};
    for (const json* bad : {&bad_theme, &bad_retention}) {
        const std::string request = args(json::array({*bad}));
        EXPECT_EQ(parse_reply(f.bridge.settings_set_device(request)).at("code"), "bad_settings") << request;
    }
    EXPECT_EQ(parse_reply(f.bridge.settings_get("[]")).at("device").at("theme"), "dark");
}

TEST(VaultBridgeSettings, VaultPreferencesLiveInTheVault) {
    fixture f;
    f.open();
    auto v = parse_reply(f.bridge.settings_get("[]")).at("vault");
    EXPECT_EQ(v.at("autoLockMinutes"), 5);
    EXPECT_EQ(v.at("clipboardClearSeconds"), 30);
    EXPECT_EQ(v.at("lockOnSessionLock"), true);
    EXPECT_EQ(v.at("lockOnMinimize"), false);

    const json changes = {{"autoLockMinutes", 15}, {"lockOnMinimize", true}};
    ASSERT_EQ(parse_reply(f.bridge.settings_set_vault(args({changes}))).at("ok"), true);
    const json out_of_range = {{"autoLockMinutes", 0}};
    EXPECT_EQ(parse_reply(f.bridge.settings_set_vault(args({out_of_range}))).at("code"), "bad_settings");

    // Saved inside the (encrypted) vault.
    pb::vault_store reopened(f.store.path(), fast_kdf());
    reopened.unlock(kPassword);
    const auto prefs = pb::vault_preferences::from(reopened.document());
    EXPECT_EQ(prefs.auto_lock_minutes, 15u);
    EXPECT_TRUE(prefs.lock_on_minimize);

    f.bridge.lock("[]");
    EXPECT_EQ(parse_reply(f.bridge.settings_set_vault(args({changes}))).at("code"), "locked");
}

TEST(VaultBridgeSettings, AutoLockFollowsThePreferences) {
    fixture f;
    EXPECT_FALSE(f.bridge.auto_lock(vault_bridge::lock_event::session_locked)); // nothing to lock
    f.open();
    EXPECT_FALSE(f.bridge.auto_lock(vault_bridge::lock_event::minimized)); // off by default
    EXPECT_TRUE(f.store.is_unlocked());
    EXPECT_TRUE(f.bridge.auto_lock(vault_bridge::lock_event::session_locked));
    EXPECT_FALSE(f.store.is_unlocked());
    EXPECT_EQ(f.locks, 1);

    f.bridge.unlock(args({kPassword}));
    const json prefs = {{"lockOnMinimize", true}, {"lockOnSessionLock", false}};
    parse_reply(f.bridge.settings_set_vault(args({prefs})));
    EXPECT_FALSE(f.bridge.auto_lock(vault_bridge::lock_event::session_locked));
    EXPECT_TRUE(f.bridge.auto_lock(vault_bridge::lock_event::minimized));
    EXPECT_EQ(f.locks, 2);
}

// ---------------------------------------------------------------------------
// Account: re-authenticated operations
// ---------------------------------------------------------------------------

TEST(VaultBridgeAccount, ChangePasswordNeedsTheCurrentOne) {
    fixture f;
    f.open();
    EXPECT_EQ(parse_reply(f.bridge.change_password(args({"wrong guess!", "a whole new password"}))).at("code"),
              "wrong_password");
    EXPECT_EQ(parse_reply(f.bridge.change_password(args({kPassword, "short"}))).at("code"), "weak_password");
    ASSERT_EQ(parse_reply(f.bridge.change_password(args({kPassword, "a whole new password"}))).at("ok"), true);

    f.bridge.lock("[]");
    EXPECT_EQ(parse_reply(f.bridge.unlock(args({kPassword}))).at("code"), "wrong_password");
    EXPECT_EQ(parse_reply(f.bridge.unlock(args({"a whole new password"}))).at("ok"), true);
}

TEST(VaultBridgeAccount, RegenerateAndRemoveRecoveryKey) {
    fixture f;
    const std::string old_key = parse_reply(f.bridge.create(args({kPassword, true}))).at("recoveryKey");
    EXPECT_EQ(parse_reply(f.bridge.regenerate_recovery_key(args({"wrong guess!"}))).at("code"), "wrong_password");
    const auto r = parse_reply(f.bridge.regenerate_recovery_key(args({kPassword})));
    ASSERT_EQ(r.at("ok"), true);
    const std::string new_key = r.at("recoveryKey");
    EXPECT_NE(new_key, old_key);

    // Only the new key opens the vault.
    f.bridge.lock("[]");
    EXPECT_EQ(parse_reply(f.bridge.recover(args({old_key, "a whole new password"}))).at("code"),
              "wrong_recovery_key");
    ASSERT_EQ(parse_reply(f.bridge.recover(args({new_key, "a whole new password"}))).at("ok"), true);

    EXPECT_EQ(parse_reply(f.bridge.remove_recovery_key(args({kPassword}))).at("code"), "wrong_password");
    ASSERT_EQ(parse_reply(f.bridge.remove_recovery_key(args({"a whole new password"}))).at("ok"), true);
    EXPECT_EQ(parse_reply(f.bridge.status("[]")).at("hasRecoveryKey"), false);
    f.bridge.lock("[]");
    EXPECT_EQ(parse_reply(f.bridge.recover(args({new_key, "another new password"}))).at("code"),
              "no_recovery_key");
}

// ---------------------------------------------------------------------------
// Backups
// ---------------------------------------------------------------------------

TEST(VaultBridgeBackups, ListAndRestoreByName) {
    fixture f;
    f.store.set_backup_interval(std::chrono::seconds(0));
    f.open();
    const auto id = f.add(sample_fields()); // backs up revision 1 (empty)
    auto changed = sample_fields();
    changed["title"] = "Changed";
    parse_reply(f.bridge.update(args({id, changed}))); // backs up revision 2

    const auto list = parse_reply(f.bridge.backups_list("[]")).at("backups");
    ASSERT_EQ(list.size(), 2u);
    for (const auto& b : list) {
        EXPECT_EQ(b.at("name").get<std::string>().find_first_of("/\\"), std::string::npos);
        EXPECT_GT(b.at("size").get<std::uint64_t>(), 0u);
    }
    const auto newest = list[0]; // newest first
    EXPECT_EQ(newest.at("revision"), 2);

    const std::string name = newest.at("name");
    EXPECT_EQ(parse_reply(f.bridge.backup_restore(args({"wrong guess!", name}))).at("code"), "wrong_password");
    for (const char* bad : {"../vault.phylaxbox", "nope.phylaxbox", ""}) {
        EXPECT_EQ(parse_reply(f.bridge.backup_restore(args({kPassword, bad}))).at("code"), "backup_not_found")
            << bad;
    }
    ASSERT_EQ(parse_reply(f.bridge.backup_restore(args({kPassword, name}))).at("ok"), true);
    EXPECT_EQ(f.store.document().entries.at(0).title, "Example");
}

TEST(VaultBridgeBackups, UnlockFromABackupWhenTheVaultIsDamaged) {
    fixture f;
    f.store.set_backup_interval(std::chrono::seconds(0));
    f.open();
    f.add(sample_fields());
    f.add(sample_fields());
    f.bridge.lock("[]");
    pb::file_io::write_file_atomic(f.store.path(), std::string_view("damaged"));
    EXPECT_EQ(parse_reply(f.bridge.unlock(args({kPassword}))).at("code"), "invalid_file");

    const auto list = parse_reply(f.bridge.backups_list("[]")).at("backups"); // works while locked
    ASSERT_FALSE(list.empty());
    const std::string name = list[0].at("name");
    EXPECT_EQ(parse_reply(f.bridge.unlock_from_backup(args({"wrong guess!", name}))).at("code"),
              "wrong_password");
    EXPECT_EQ(parse_reply(f.bridge.unlock_from_backup(args({kPassword, "x.phylaxbox"}))).at("code"),
              "backup_not_found");
    const auto r = parse_reply(f.bridge.unlock_from_backup(args({kPassword, name})));
    ASSERT_EQ(r.at("ok"), true) << r.dump();
    EXPECT_EQ(r.at("entries"), 1);
    EXPECT_TRUE(f.store.is_unlocked());
}

// ---------------------------------------------------------------------------
// Vault location
// ---------------------------------------------------------------------------

TEST(VaultBridgeLocation, ChooseAnotherVaultFile) {
    fixture f;
    f.open();
    // Cancelled: nothing changes.
    auto r = parse_reply(f.bridge.choose_vault(args({"open", "Open", "Vault"})));
    EXPECT_EQ(r.at("cancelled"), true);
    EXPECT_TRUE(f.store.is_unlocked());
    ASSERT_EQ(f.dialogs.size(), 1u);
    EXPECT_FALSE(f.dialogs[0].save);
    EXPECT_EQ(f.dialogs[0].title, "Open");

    const auto other = f.dir.path() / u8"outro lugar" / u8"cofre é.phylaxbox";
    std::filesystem::create_directories(other.parent_path());
    const auto u8 = other.u8string();
    f.dialog_answer = std::string(u8.begin(), u8.end());
    r = parse_reply(f.bridge.choose_vault(args({"create", "Create", "Vault"})));
    ASSERT_EQ(r.at("ok"), true) << r.dump();
    EXPECT_EQ(r.at("exists"), false);
    EXPECT_TRUE(f.dialogs.back().save);
    EXPECT_FALSE(f.store.is_unlocked()); // the previous vault was locked
    EXPECT_EQ(f.locks, 1);
    EXPECT_EQ(f.store.path(), other);

    // Remembered for the next start.
    EXPECT_EQ(pb::device_settings::load(f.settings_file).effective_vault_path(), other);
    ASSERT_EQ(parse_reply(f.bridge.create(args({kPassword, false}))).at("ok"), true);
    EXPECT_TRUE(std::filesystem::exists(other));

    // Back to the default location.
    r = parse_reply(f.bridge.use_default_vault("[]"));
    ASSERT_EQ(r.at("ok"), true);
    EXPECT_EQ(f.store.path(), pb::vault_store::default_path());
    EXPECT_TRUE(pb::device_settings::load(f.settings_file).vault_path.empty());

    EXPECT_EQ(parse_reply(f.bridge.choose_vault(args({"delete", "x", "y"}))).at("code"), "bad_request");
    f.dialog_answer = "relative/path.phylaxbox";
    EXPECT_EQ(parse_reply(f.bridge.choose_vault(args({"open", "x", "y"}))).at("code"), "bad_request");
}

TEST(VaultBridgeLocation, NoDialogAvailable) {
    temp_dir dir;
    vault_store store{dir.path() / "vault.phylaxbox", fast_kdf()};
    vault_bridge bridge{store, kDevice, dir.path() / "settings.json"};
    EXPECT_EQ(parse_reply(bridge.choose_vault(args({"open", "x", "y"}))).at("code"), "dialog_unavailable");
}
