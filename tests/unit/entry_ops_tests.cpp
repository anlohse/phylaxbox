#include "models/entry_ops.h"
#include "models/pbexceptions.h"
#include "storage/device_id.h"
#include "storage/file_io.h"
#include "test_helpers.h"

#include <gtest/gtest.h>

#include <string>

using namespace pb;

namespace {

const std::string kDevice = "0b6e1c1a-3f5d-4a8e-9c2b-7d4e5f6a7b8c";
const std::string kOtherDevice = "9b6e1c1a-3f5d-4a8e-9c2b-7d4e5f6a7b8c";
const std::string kT1 = "2026-11-18T10:00:00.000Z";
const std::string kT2 = "2026-11-18T11:00:00.000Z";

entry_fields sample() {
    entry_fields f;
    f.title = "Example";
    f.username = "alice";
    f.password = "hunter2";
    f.urls = {"https://example.com/login"};
    f.notes = "line 1\nline 2";
    f.tags = {"work"};
    return f;
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

TEST(EntryOps, AddSetsMetadata) {
    vault_document doc;
    const auto id = add_entry(doc, sample(), kDevice, kT1);
    ASSERT_EQ(doc.entries.size(), 1u);
    const auto& e = doc.entries[0];
    EXPECT_EQ(e.id, id);
    EXPECT_TRUE(is_canonical_uuid(e.id));
    EXPECT_EQ(e.title, "Example");
    EXPECT_EQ(e.password, "hunter2");
    EXPECT_EQ(e.created_at, kT1);
    EXPECT_EQ(e.updated_at, kT1);
    EXPECT_EQ(e.revision, 1u);
    EXPECT_EQ(e.device_id, kDevice);
    EXPECT_NO_THROW(doc.validate());
}

TEST(EntryOps, UpdateBumpsRevisionAndKeepsCreation) {
    vault_document doc;
    const auto id = add_entry(doc, sample(), kDevice, kT1);
    auto changed = sample();
    changed.password = "correct horse";
    update_entry(doc, id, changed, kOtherDevice, kT2);
    const auto& e = doc.entries[0];
    EXPECT_EQ(e.password, "correct horse");
    EXPECT_EQ(e.revision, 2u);
    EXPECT_EQ(e.created_at, kT1);
    EXPECT_EQ(e.updated_at, kT2);
    EXPECT_EQ(e.device_id, kOtherDevice);
}

TEST(EntryOps, FavoriteOnlyCountsRealChanges) {
    vault_document doc;
    const auto id = add_entry(doc, sample(), kDevice, kT1);
    set_favorite(doc, id, false, kDevice, kT2); // unchanged
    EXPECT_EQ(doc.entries[0].revision, 1u);
    set_favorite(doc, id, true, kDevice, kT2);
    EXPECT_TRUE(doc.entries[0].favorite);
    EXPECT_EQ(doc.entries[0].revision, 2u);
}

TEST(EntryOps, DeleteLeavesATombstoneWithoutSecrets) {
    vault_document doc;
    const auto id = add_entry(doc, sample(), kDevice, kT1);
    update_entry(doc, id, sample(), kDevice, kT1); // revision 2
    delete_entry(doc, id, kOtherDevice, kT2);
    EXPECT_TRUE(doc.entries.empty());
    ASSERT_EQ(doc.tombstones.size(), 1u);
    const auto& t = doc.tombstones[0];
    EXPECT_EQ(t.id, id);
    EXPECT_EQ(t.deleted_at, kT2);
    EXPECT_EQ(t.revision, 3u);
    EXPECT_EQ(t.device_id, kOtherDevice);
    EXPECT_NO_THROW(doc.validate());
    EXPECT_EQ(view(doc.to_json()).find("hunter2"), std::string_view::npos);
}

TEST(EntryOps, UnknownIds) {
    vault_document doc;
    const std::string missing = "6f9619ff-8b86-4d01-b42d-00c04fc964ff";
    EXPECT_EQ(error_code([&] { update_entry(doc, missing, sample(), kDevice, kT1); }),
              ErrorCodes::ENTRY_NOT_FOUND);
    EXPECT_EQ(error_code([&] { delete_entry(doc, missing, kDevice, kT1); }),
              ErrorCodes::ENTRY_NOT_FOUND);
    EXPECT_EQ(error_code([&] { set_favorite(doc, missing, true, kDevice, kT1); }),
              ErrorCodes::ENTRY_NOT_FOUND);
}

TEST(EntryOps, NormalizationTrimsAndCleansLists) {
    entry_fields f = sample();
    f.title = "  Example  ";
    f.username = " alice\t";
    f.password = "  spaces are part of passwords  ";
    f.urls = {" https://a ", "", "  "};
    f.tags = {"work", " work ", "", "home"};
    normalize_and_validate(f);
    EXPECT_EQ(f.title, "Example");
    EXPECT_EQ(f.username, "alice");
    EXPECT_EQ(f.password, "  spaces are part of passwords  "); // never trimmed
    ASSERT_EQ(f.urls.size(), 1u);
    EXPECT_EQ(f.urls[0], "https://a");
    ASSERT_EQ(f.tags.size(), 2u);
    EXPECT_EQ(f.tags[0], "work");
    EXPECT_EQ(f.tags[1], "home");
}

TEST(EntryOps, ValidationErrors) {
    auto expect_invalid = [](entry_fields f) {
        EXPECT_EQ(error_code([&] { normalize_and_validate(f); }), ErrorCodes::INVALID_ENTRY);
    };
    entry_fields f = sample();
    f.title = "   ";
    expect_invalid(f);
    f = sample();
    f.title = secure_string(entry_limits::TITLE + 1, 'x');
    expect_invalid(f);
    f = sample();
    f.password = secure_string(entry_limits::PASSWORD + 1, 'x');
    expect_invalid(f);
    f = sample();
    f.tags.assign(entry_limits::TAGS + 1, "t");
    for (std::size_t i = 0; i < f.tags.size(); ++i) f.tags[i] += to_secure(std::to_string(i));
    expect_invalid(f);
    f = sample();
    f.notes = "\xC3"; // truncated UTF-8
    expect_invalid(f);

    // Limits count code points, not bytes.
    f = sample();
    f.title.clear();
    for (std::size_t i = 0; i < entry_limits::TITLE; ++i) f.title += "\xC3\xA4";
    EXPECT_NO_THROW(normalize_and_validate(f));
}

TEST(EntryOps, AddRejectsInvalidInputWithoutChangingTheDocument) {
    vault_document doc;
    entry_fields f = sample();
    f.title.clear();
    EXPECT_EQ(error_code([&] { add_entry(doc, f, kDevice, kT1); }), ErrorCodes::INVALID_ENTRY);
    EXPECT_TRUE(doc.entries.empty());
}

TEST(DeviceId, CreatedOnceThenReused) {
    pb_test::temp_dir dir;
    const auto file = dir.path() / "device-id";
    const auto first = load_or_create_device_id(file);
    EXPECT_TRUE(is_canonical_uuid(first));
    EXPECT_EQ(load_or_create_device_id(file), first);

    file_io::write_file_atomic(file, std::string_view("not-a-uuid"));
    const auto replaced = load_or_create_device_id(file);
    EXPECT_TRUE(is_canonical_uuid(replaced));
    EXPECT_NE(replaced, first);
}
