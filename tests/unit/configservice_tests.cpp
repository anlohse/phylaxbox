#include "storage/configservice.h"
#include "storage/file_io.h"
#include "models/pbexceptions.h"
#include "test_helpers.h"

#include <gtest/gtest.h>

#include <string>

using pb_test::fast_kdf;
using pb_test::temp_dir;

TEST(ConfigService, CreateThenLoad) {
    temp_dir dir;
    const auto path = dir.path() / "nested" / "config.pbx";

    PBConfiguration cfg;
    cfg.sync_engine = DROPBOX;
    cfg.sync_token = "sl.token-123";

    {
        config_service svc(path, fast_kdf());
        EXPECT_FALSE(svc.exists());
        svc.create("master", cfg);
        EXPECT_TRUE(svc.exists());
        EXPECT_TRUE(svc.is_unlocked());
    }

    config_service svc(path, fast_kdf());
    EXPECT_FALSE(svc.is_unlocked());
    svc.load("master");
    EXPECT_EQ(svc.get_config().sync_engine, DROPBOX);
    EXPECT_EQ(svc.get_config().sync_token, "sl.token-123");
}

TEST(ConfigService, TokenIsNotStoredInClear) {
    temp_dir dir;
    const auto path = dir.path() / "config.pbx";
    PBConfiguration cfg;
    cfg.sync_engine = G_DRIVE;
    cfg.sync_token = "TOKEN-MARKER-0123456789";
    config_service(path, fast_kdf()).create("master", cfg);

    const auto bytes = pb::file_io::read_file(path);
    const std::string raw(bytes.begin(), bytes.end());
    EXPECT_EQ(raw.find("TOKEN-MARKER"), std::string::npos);
    EXPECT_EQ(raw.rfind("PHYLAXBX", 0), 0u);
}

TEST(ConfigService, SaveOverwritesAtomically) {
    temp_dir dir;
    const auto path = dir.path() / "config.pbx";
    config_service svc(path, fast_kdf());
    svc.create("master");

    PBConfiguration cfg;
    cfg.sync_engine = DROPBOX;
    cfg.sync_token = "second";
    svc.set_config(cfg).save();

    EXPECT_FALSE(std::filesystem::exists(path.string() + ".tmp"));
    config_service reader(path, fast_kdf());
    reader.load("master");
    EXPECT_EQ(reader.get_config().sync_token, "second");
}

TEST(ConfigService, WrongPassword) {
    temp_dir dir;
    const auto path = dir.path() / "config.pbx";
    config_service(path, fast_kdf()).create("master");

    config_service svc(path, fast_kdf());
    EXPECT_THROW(svc.load("not master"), wrong_password_exception);
    EXPECT_FALSE(svc.is_unlocked());
}

TEST(ConfigService, MissingFile) {
    temp_dir dir;
    config_service svc(dir.path() / "absent.pbx", fast_kdf());
    EXPECT_THROW(svc.load("master"), ioexception);
}

TEST(ConfigService, SaveWhileLockedThrows) {
    temp_dir dir;
    config_service svc(dir.path() / "config.pbx", fast_kdf());
    EXPECT_THROW(svc.save(), pbexception);

    svc.create("master");
    svc.lock();
    EXPECT_FALSE(svc.is_unlocked());
    EXPECT_THROW(svc.save(), pbexception);
}

TEST(ConfigService, VaultFileIsNotAcceptedAsConfig) {
    temp_dir dir;
    const auto path = dir.path() / "config.pbx";
    auto c = pb::vault_container::create("master", pb::content_type::vault, fast_kdf());
    pb::file_io::write_file_atomic(path, c.seal(std::string_view("{}")));

    config_service svc(path, fast_kdf());
    EXPECT_THROW(svc.load("master"), vault_format_exception);
}

TEST(FileIo, DefaultDataDirIsAbsolute) {
    EXPECT_TRUE(pb::file_io::default_data_dir().is_absolute());
}
