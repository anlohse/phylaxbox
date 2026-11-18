#include "models/pbexceptions.h"
#include "storage/file_io.h"
#include "storage/vault_store.h"
#include "test_helpers.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <string>

using namespace pb;
using pb_test::fast_kdf;
using pb_test::temp_dir;

namespace {

const std::string kPassword = "correct horse battery";

vault_entry sample_entry() {
    vault_entry e;
    e.id = new_uuid();
    e.title = "Example";
    e.password = "hunter2";
    e.created_at = e.updated_at = utc_now();
    e.device_id = new_uuid();
    return e;
}

int error_code(const std::function<void()>& f) {
    try {
        f();
    } catch (const pbexception& e) {
        return e.errorcode();
    }
    return 0;
}

} // namespace

TEST(VaultStore, CreateThenUnlock) {
    temp_dir dir;
    const auto path = dir.path() / "sub" / "vault.phylaxbox";
    {
        vault_store store(path, fast_kdf());
        EXPECT_FALSE(store.exists());
        const auto key = store.create(kPassword, false);
        EXPECT_FALSE(key.has_value());
        EXPECT_TRUE(store.exists());
        EXPECT_TRUE(store.is_unlocked());
        EXPECT_TRUE(store.document().entries.empty());
    }
    vault_store store(path, fast_kdf());
    EXPECT_FALSE(store.is_unlocked());
    store.unlock(kPassword);
    EXPECT_TRUE(store.is_unlocked());
    EXPECT_EQ(store.container().revision(), 1u);
}

TEST(VaultStore, SaveAndReload) {
    temp_dir dir;
    const auto path = dir.path() / "vault.phylaxbox";
    vault_store store(path, fast_kdf());
    store.create(kPassword, false);
    store.document().entries.push_back(sample_entry());
    store.save();

    vault_store other(path, fast_kdf());
    other.unlock(kPassword);
    ASSERT_EQ(other.document().entries.size(), 1u);
    EXPECT_EQ(other.document().entries[0].password, "hunter2");
    EXPECT_EQ(other.container().revision(), 2u);
}

TEST(VaultStore, SaveKeepsThePreviousVersionAsBackup) {
    temp_dir dir;
    const auto path = dir.path() / "vault.phylaxbox";
    vault_store store(path, fast_kdf());
    store.create(kPassword, false);
    EXPECT_FALSE(std::filesystem::exists(store.backup_path())); // nothing to back up yet
    const auto first = file_io::read_file(path);

    store.document().entries.push_back(sample_entry());
    store.save();
    EXPECT_EQ(file_io::read_file(store.backup_path()), first);
    EXPECT_FALSE(std::filesystem::exists(path.string() + ".tmp"));

    // The backup is a valid, older version of the same vault.
    vault_store backup(store.backup_path(), fast_kdf());
    backup.unlock(kPassword);
    EXPECT_TRUE(backup.document().entries.empty());
    EXPECT_EQ(backup.container().id(), store.container().id());
}

TEST(VaultStore, CreateRefusesToOverwrite) {
    temp_dir dir;
    const auto path = dir.path() / "vault.phylaxbox";
    vault_store(path, fast_kdf()).create(kPassword, false);
    const auto before = file_io::read_file(path);
    vault_store again(path, fast_kdf());
    EXPECT_EQ(error_code([&] { again.create("another password", false); }),
              ErrorCodes::VAULT_EXISTS);
    EXPECT_EQ(file_io::read_file(path), before);
}

TEST(VaultStore, WeakPasswordsAreRejected) {
    temp_dir dir;
    vault_store store(dir.path() / "vault.phylaxbox", fast_kdf());
    EXPECT_EQ(error_code([&] { store.create("1234567", false); }), ErrorCodes::WEAK_PASSWORD);
    EXPECT_FALSE(store.exists());
    // 8 code points, more than 8 bytes: accepted.
    EXPECT_NO_THROW(store.create("\xC3\xA4\xC3\xA4\xC3\xA4\xC3\xA4\xC3\xA4\xC3\xA4\xC3\xA4\xC3\xA4", false));
    EXPECT_EQ(vault_store::password_length("\xC3\xA4\xE2\x9C\x93x"), 3u);
}

TEST(VaultStore, WrongPasswordLeavesItLocked) {
    temp_dir dir;
    const auto path = dir.path() / "vault.phylaxbox";
    vault_store(path, fast_kdf()).create(kPassword, false);
    vault_store store(path, fast_kdf());
    EXPECT_THROW(store.unlock("wrong password"), wrong_password_exception);
    EXPECT_FALSE(store.is_unlocked());
    EXPECT_EQ(error_code([&] { store.document(); }), ErrorCodes::VAULT_LOCKED);
}

TEST(VaultStore, MissingFile) {
    temp_dir dir;
    vault_store store(dir.path() / "absent.phylaxbox", fast_kdf());
    EXPECT_THROW(store.unlock(kPassword), ioexception);
}

TEST(VaultStore, RecoverWithRecoveryKeyAndSetNewPassword) {
    temp_dir dir;
    const auto path = dir.path() / "vault.phylaxbox";
    std::string key_text;
    {
        vault_store store(path, fast_kdf());
        const auto key = store.create(kPassword, true);
        ASSERT_TRUE(key.has_value());
        key_text = key->to_text();
        store.document().entries.push_back(sample_entry());
        store.save();
    }
    vault_store store(path, fast_kdf());
    store.unlock_with_recovery_key(recovery_key::parse(key_text));
    store.change_password("a brand new password");

    vault_store reopened(path, fast_kdf());
    EXPECT_THROW(reopened.unlock(kPassword), wrong_password_exception);
    reopened.unlock("a brand new password");
    EXPECT_EQ(reopened.document().entries.size(), 1u);
    // The same recovery key still works after the password change.
    reopened.lock();
    EXPECT_NO_THROW(reopened.unlock_with_recovery_key(recovery_key::parse(key_text)));
}

TEST(VaultStore, LockForgetsEverything) {
    temp_dir dir;
    vault_store store(dir.path() / "vault.phylaxbox", fast_kdf());
    store.create(kPassword, false);
    store.lock();
    EXPECT_FALSE(store.is_unlocked());
    EXPECT_EQ(error_code([&] { store.save(); }), ErrorCodes::VAULT_LOCKED);
    EXPECT_EQ(error_code([&] { store.change_password("long enough"); }),
              ErrorCodes::VAULT_LOCKED);
}

TEST(VaultStore, CorruptedFileIsAnIntegrityError) {
    temp_dir dir;
    const auto path = dir.path() / "vault.phylaxbox";
    vault_store(path, fast_kdf()).create(kPassword, false);
    auto bytes = file_io::read_file(path);
    bytes.back() ^= 0x01;
    file_io::write_file_atomic(path, bytes);
    vault_store store(path, fast_kdf());
    EXPECT_THROW(store.unlock(kPassword), integrity_exception);
}

TEST(VaultStore, DefaultPathUsesTheDataDirectory) {
    const auto p = vault_store::default_path();
    EXPECT_TRUE(p.is_absolute());
    EXPECT_EQ(p.filename(), "vault.phylaxbox");
}
