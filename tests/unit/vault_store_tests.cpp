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
    EXPECT_TRUE(store.backups().empty()); // nothing to back up yet
    const auto first = file_io::read_file(path);

    store.document().entries.push_back(sample_entry());
    store.save();
    const auto backups = store.backups();
    ASSERT_EQ(backups.size(), 1u);
    EXPECT_EQ(backups[0].path.parent_path(), dir.path() / "backups");
    EXPECT_EQ(backups[0].revision, 1u); // the version that was replaced
    EXPECT_TRUE(is_utc_timestamp(backups[0].saved_at)) << backups[0].saved_at;
    EXPECT_EQ(backups[0].size, first.size());
    EXPECT_EQ(file_io::read_file(backups[0].path), first);
    EXPECT_FALSE(std::filesystem::exists(path.string() + ".tmp"));

    // The backup is a valid, older version of the same vault.
    vault_store backup(backups[0].path, fast_kdf());
    backup.unlock(kPassword);
    EXPECT_TRUE(backup.document().entries.empty());
    EXPECT_EQ(backup.container().id(), store.container().id());
}

TEST(VaultStore, BackupsAreListedNewestFirstAndPruned) {
    temp_dir dir;
    vault_store store(dir.path() / "vault.phylaxbox", fast_kdf());
    store.set_backup_retention(3);
    store.create(kPassword, false); // revision 1
    for (int i = 0; i < 5; ++i) store.save(); // revisions 2..6; backs up 1..5
    const auto backups = store.backups();
    ASSERT_EQ(backups.size(), 3u);
    EXPECT_EQ(backups[0].revision, 5u);
    EXPECT_EQ(backups[1].revision, 4u);
    EXPECT_EQ(backups[2].revision, 3u);

    store.set_backup_retention(0); // clamped to 1
    EXPECT_EQ(store.backup_retention(), 1u);
}

TEST(VaultStore, UnrelatedFilesInTheBackupsFolderAreIgnoredAndKept) {
    temp_dir dir;
    vault_store store(dir.path() / "vault.phylaxbox", fast_kdf());
    store.set_backup_retention(1);
    store.create(kPassword, false);
    const auto folder = dir.path() / "backups";
    for (const char* name : {"notes.txt", "vault-garbage-r1.phylaxbox", "other-20261118T170102123Z-r1.phylaxbox",
                             "vault-20261118T170102123Z-rX.phylaxbox"}) {
        file_io::write_file_atomic(folder / name, std::string_view("x"));
    }
    store.save();
    store.save();
    EXPECT_EQ(store.backups().size(), 1u);
    for (const char* name : {"notes.txt", "vault-garbage-r1.phylaxbox", "other-20261118T170102123Z-r1.phylaxbox",
                             "vault-20261118T170102123Z-rX.phylaxbox"}) {
        EXPECT_TRUE(std::filesystem::exists(folder / name)) << name; // never deleted
    }
}

TEST(VaultStore, RestoreBackupAsANewRevisionAndUndo) {
    temp_dir dir;
    vault_store store(dir.path() / "vault.phylaxbox", fast_kdf());
    store.create(kPassword, false); // r1: empty
    store.document().entries.push_back(sample_entry());
    store.save(); // r2: one entry
    store.document().entries.clear();
    store.save(); // r3: empty again (accidental delete)

    const auto with_entry = store.backups()[0]; // r2
    ASSERT_EQ(with_entry.revision, 2u);
    store.restore_backup(with_entry.path);
    EXPECT_EQ(store.document().entries.size(), 1u);
    EXPECT_EQ(store.container().revision(), 4u); // restored as a new revision, not a rollback

    vault_store reopened(store.path(), fast_kdf());
    reopened.unlock(kPassword);
    EXPECT_EQ(reopened.document().entries.size(), 1u);

    // The version that was replaced by the restore is itself backed up.
    EXPECT_EQ(store.backups()[0].revision, 3u);
}

TEST(VaultStore, RestoreRejectsForeignOrDamagedBackups) {
    temp_dir dir;
    vault_store store(dir.path() / "vault.phylaxbox", fast_kdf());
    store.create(kPassword, false);
    store.save();
    const auto before = file_io::read_file(store.path());

    // Another vault, even with the same password.
    temp_dir other_dir;
    vault_store other(other_dir.path() / "vault.phylaxbox", fast_kdf());
    other.create(kPassword, false);
    EXPECT_THROW(store.restore_backup(other.path()), integrity_exception);

    // A tampered backup of this vault.
    const auto backup = store.backups()[0].path;
    auto bytes = file_io::read_file(backup);
    bytes.back() ^= 1;
    file_io::write_file_atomic(backup, bytes);
    EXPECT_THROW(store.restore_backup(backup), integrity_exception);

    EXPECT_EQ(file_io::read_file(store.path()), before); // nothing was written
    store.lock();
    EXPECT_EQ(error_code([&] { store.restore_backup(backup); }), ErrorCodes::VAULT_LOCKED);
}

TEST(VaultStore, BackupsSurviveAPasswordChange) {
    temp_dir dir;
    vault_store store(dir.path() / "vault.phylaxbox", fast_kdf());
    store.create(kPassword, false);
    store.document().entries.push_back(sample_entry());
    store.save();
    store.change_password("a different password");
    // The newest backup was written under the old password; the vault key is
    // the same, so it restores while unlocked with the new one.
    EXPECT_NO_THROW(store.restore_backup(store.backups()[0].path));
    EXPECT_EQ(store.document().entries.size(), 1u);
}

TEST(VaultStore, UnlockFromBackupWhenTheVaultFileIsDamaged) {
    temp_dir dir;
    const auto path = dir.path() / "vault.phylaxbox";
    {
        vault_store store(path, fast_kdf());
        store.create(kPassword, false);
        store.document().entries.push_back(sample_entry());
        store.save();
        store.save();
    }
    auto bytes = file_io::read_file(path);
    bytes[bytes.size() / 2] ^= 1;
    file_io::write_file_atomic(path, bytes);

    vault_store store(path, fast_kdf());
    EXPECT_THROW(store.unlock(kPassword), integrity_exception);
    const auto backup = store.backups()[0];

    EXPECT_THROW(store.unlock_from_backup("wrong password", backup.path), wrong_password_exception);
    EXPECT_EQ(file_io::read_file(path), bytes); // untouched on failure

    store.unlock_from_backup(kPassword, backup.path);
    EXPECT_TRUE(store.is_unlocked());
    EXPECT_EQ(store.document().entries.size(), 1u);

    // The damaged file was kept aside, the vault opens normally again.
    bool damaged_kept = false;
    for (const auto& item : std::filesystem::directory_iterator(dir.path())) {
        if (item.path().filename().string().rfind("vault.phylaxbox.damaged-", 0) == 0) {
            damaged_kept = file_io::read_file(item.path()) == bytes;
        }
    }
    EXPECT_TRUE(damaged_kept);
    vault_store reopened(path, fast_kdf());
    EXPECT_NO_THROW(reopened.unlock(kPassword));
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

TEST(VaultStore, SavePurgesExpiredTombstones) {
    temp_dir dir;
    vault_store store(dir.path() / "vault.phylaxbox", fast_kdf());
    store.create(kPassword, false);
    tombstone old_one, recent;
    old_one.id = new_uuid();
    old_one.deleted_at = "2020-01-01T00:00:00Z"; // years ago
    old_one.device_id = new_uuid();
    recent.id = new_uuid();
    recent.deleted_at = utc_now();
    recent.device_id = new_uuid();
    store.document().tombstones = {old_one, recent};
    store.save();

    vault_store reopened(store.path(), fast_kdf());
    reopened.unlock(kPassword);
    ASSERT_EQ(reopened.document().tombstones.size(), 1u);
    EXPECT_EQ(reopened.document().tombstones[0].id, recent.id);
}
