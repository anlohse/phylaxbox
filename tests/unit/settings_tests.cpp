#include "models/pbexceptions.h"
#include "models/vault_preferences.h"
#include "storage/device_settings.h"
#include "storage/file_io.h"
#include "storage/vault_store.h"
#include "test_helpers.h"

#include <gtest/gtest.h>

using namespace pb;
using pb_test::fast_kdf;
using pb_test::temp_dir;

TEST(DeviceSettings, DefaultsWhenMissingOrGarbage) {
    temp_dir dir;
    const auto file = dir.path() / "settings.json";
    auto s = device_settings::load(file);
    EXPECT_EQ(s.theme, "system");
    EXPECT_EQ(s.language, "system");
    EXPECT_TRUE(s.vault_path.empty());
    EXPECT_EQ(s.backup_retention, 10u);
    EXPECT_EQ(s.effective_vault_path(), vault_store::default_path());

    file_io::write_file_atomic(file, std::string_view("not json"));
    EXPECT_EQ(device_settings::load(file).theme, "system");
}

TEST(DeviceSettings, RoundTripAndFieldByFieldFallback) {
    temp_dir dir;
    const auto file = dir.path() / "settings.json";
    device_settings s;
    s.theme = "dark";
    s.language = "en";
    const auto u8 = (dir.path() / std::filesystem::path(u8"cofre é.phylaxbox")).u8string();
    s.vault_path = std::string(u8.begin(), u8.end()); // settings keep paths as UTF-8
    s.backup_retention = 25;
    s.save(file);

    const auto loaded = device_settings::load(file);
    EXPECT_EQ(loaded.theme, "dark");
    EXPECT_EQ(loaded.language, "en");
    EXPECT_EQ(loaded.vault_path, s.vault_path);
    EXPECT_EQ(loaded.backup_retention, 25u);
    const auto name = loaded.effective_vault_path().filename().u8string();
    EXPECT_EQ(std::string(name.begin(), name.end()), "cofre é.phylaxbox");

    // One bad field does not discard the others.
    file_io::write_file_atomic(file, std::string_view(
        R"({"theme":"neon","language":"en","backupRetention":0,"vaultPath":"relative.phylaxbox"})"));
    const auto partial = device_settings::load(file);
    EXPECT_EQ(partial.theme, "system");
    EXPECT_EQ(partial.language, "en");
    EXPECT_EQ(partial.backup_retention, 10u);
    EXPECT_TRUE(partial.vault_path.empty());
}

TEST(DeviceSettings, SaveValidates) {
    temp_dir dir;
    device_settings s;
    s.theme = "neon";
    EXPECT_THROW(s.save(dir.path() / "settings.json"), std::invalid_argument);
    s = {};
    s.backup_retention = 101;
    EXPECT_THROW(s.validate(), std::invalid_argument);
    s = {};
    s.vault_path = "relative/path.phylaxbox";
    EXPECT_THROW(s.validate(), std::invalid_argument);
}

TEST(VaultPreferences, DefaultsReadAndWrite) {
    vault_document doc;
    auto p = vault_preferences::from(doc);
    EXPECT_EQ(p.auto_lock_minutes, 5u);
    EXPECT_EQ(p.clipboard_clear_seconds, 30u);
    EXPECT_FALSE(p.lock_on_minimize);
    EXPECT_TRUE(p.lock_on_session_lock);

    doc.preferences["somethingElse"] = "kept";
    p.auto_lock_minutes = 15;
    p.clipboard_clear_seconds = 60;
    p.lock_on_minimize = true;
    p.apply_to(doc);
    const auto back = vault_preferences::from(vault_document::from_json(pb::view(doc.to_json())));
    EXPECT_EQ(back.auto_lock_minutes, 15u);
    EXPECT_EQ(back.clipboard_clear_seconds, 60u);
    EXPECT_TRUE(back.lock_on_minimize);
    EXPECT_EQ(doc.preferences.at("somethingElse"), "kept");
}

TEST(VaultPreferences, InvalidValuesFallBackAndCannotBeWritten) {
    vault_document doc;
    doc.preferences["autoLockMinutes"] = 0;
    doc.preferences["clipboardClearSeconds"] = "30";
    doc.preferences["lockOnMinimize"] = 1;
    const auto p = vault_preferences::from(doc);
    EXPECT_EQ(p.auto_lock_minutes, 5u);
    EXPECT_EQ(p.clipboard_clear_seconds, 30u);
    EXPECT_FALSE(p.lock_on_minimize);

    vault_preferences bad;
    bad.auto_lock_minutes = 121;
    EXPECT_THROW(bad.apply_to(doc), std::invalid_argument);
    bad = {};
    bad.clipboard_clear_seconds = 5;
    EXPECT_THROW(bad.validate(), std::invalid_argument);
}

// ---------------------------------------------------------------------------
// Re-authentication, recovery key management, switching files
// ---------------------------------------------------------------------------

TEST(VaultStoreAccount, VerifyPassword) {
    temp_dir dir;
    vault_store store(dir.path() / "vault.phylaxbox", fast_kdf());
    store.create("correct horse battery", false);
    EXPECT_TRUE(store.verify_password("correct horse battery"));
    EXPECT_FALSE(store.verify_password("wrong password"));
    EXPECT_FALSE(store.verify_password(""));
    store.change_password("a new long password");
    EXPECT_FALSE(store.verify_password("correct horse battery"));
    EXPECT_TRUE(store.verify_password("a new long password"));
}

TEST(VaultStoreAccount, RegenerateAndRemoveRecoveryKey) {
    temp_dir dir;
    const auto path = dir.path() / "vault.phylaxbox";
    vault_store store(path, fast_kdf());
    const auto first = store.create("correct horse battery", true);
    const auto second = store.regenerate_recovery_key();
    EXPECT_NE(first->to_text(), second.to_text());

    vault_store other(path, fast_kdf());
    EXPECT_THROW(other.unlock_with_recovery_key(*first), wrong_password_exception);
    EXPECT_NO_THROW(other.unlock_with_recovery_key(second));
    other.lock();

    store.remove_recovery_key();
    EXPECT_FALSE(store.container().has_recovery_key());
    try {
        other.unlock_with_recovery_key(second);
        FAIL() << "expected NO_RECOVERY_SLOT";
    } catch (const pbexception& e) {
        EXPECT_EQ(e.errorcode(), ErrorCodes::NO_RECOVERY_SLOT);
    }
    EXPECT_NO_THROW(other.unlock("correct horse battery"));
}

TEST(VaultStoreAccount, SwitchFilesOnlyWhileLocked) {
    temp_dir dir;
    vault_store store(dir.path() / "a.phylaxbox", fast_kdf());
    store.create("correct horse battery", false);
    EXPECT_THROW(store.set_path(dir.path() / "b.phylaxbox"), pbexception);
    store.lock();
    store.set_path(dir.path() / "b.phylaxbox");
    EXPECT_FALSE(store.exists());
    store.create("another long password", false);
    store.lock();
    store.set_path(dir.path() / "a.phylaxbox");
    EXPECT_NO_THROW(store.unlock("correct horse battery"));
}
