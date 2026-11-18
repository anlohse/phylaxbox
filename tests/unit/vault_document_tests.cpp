#include "models/pbexceptions.h"
#include "models/vault_document.h"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <regex>
#include <set>

using namespace pb;
using json = nlohmann::json;

namespace {

const std::string kDevice = "0b6e1c1a-3f5d-4a8e-9c2b-7d4e5f6a7b8c";
const std::string kTime = "2026-11-17T12:00:00.000Z";

vault_entry make_entry(const std::string& id) {
    vault_entry e;
    e.id = id;
    e.title = "Example";
    e.username = "alice";
    e.password = "hunter2";
    e.urls = {"https://example.com/login"};
    e.tags = {"work"};
    e.created_at = kTime;
    e.updated_at = kTime;
    e.device_id = kDevice;
    return e;
}

json minimal_entry(const std::string& id) {
    return {{"id", id},
            {"createdAt", kTime},
            {"updatedAt", kTime},
            {"revision", 1},
            {"deviceId", kDevice}};
}

// Returns the error code and checks the message, so a test cannot pass
// because of an unrelated error (e.g. a malformed fixture).
int format_error(const std::string& text, const char* expected_in_message = nullptr) {
    try {
        vault_document::from_json(text);
    } catch (const vault_format_exception& e) {
        if (expected_in_message) {
            EXPECT_NE(std::string(e.what()).find(expected_in_message), std::string::npos)
                << e.what();
        }
        return e.errorcode();
    }
    return 0;
}

// Takes a vector: with nlohmann::json, `json x = {obj}` (one element) yields
// the object itself, not a one-element array.
json doc_with_entries(const std::vector<json>& entries) {
    json root = json::object();
    root["schema"] = 1;
    root["entries"] = json::array();
    for (const auto& e : entries) root["entries"].push_back(e);
    return root;
}

} // namespace

TEST(VaultDocument, RoundTrip) {
    vault_document doc;
    doc.entries.push_back(make_entry(new_uuid()));
    doc.entries.back().notes = "multi\nline \xC3\xA9";
    doc.entries.back().favorite = true;
    tombstone t;
    t.id = new_uuid();
    t.deleted_at = kTime;
    t.revision = 3;
    t.device_id = kDevice;
    doc.tombstones.push_back(t);
    doc.preferences["autoLockMinutes"] = 5;

    const auto parsed = vault_document::from_json(doc.to_json());
    ASSERT_EQ(parsed.entries.size(), 1u);
    const auto& e = parsed.entries[0];
    EXPECT_EQ(e.id, doc.entries[0].id);
    EXPECT_EQ(e.password, "hunter2");
    EXPECT_EQ(e.notes, "multi\nline \xC3\xA9");
    ASSERT_EQ(e.urls.size(), 1u);
    EXPECT_EQ(e.urls[0], "https://example.com/login");
    EXPECT_TRUE(e.favorite);
    ASSERT_EQ(parsed.tombstones.size(), 1u);
    EXPECT_EQ(parsed.tombstones[0].revision, 3u);
    EXPECT_EQ(parsed.preferences.at("autoLockMinutes"), 5);
    EXPECT_EQ(parsed.to_json(), doc.to_json());
}

TEST(VaultDocument, MinimalEntryUsesDefaults) {
    const auto doc = vault_document::from_json(
        doc_with_entries({minimal_entry("6f9619ff-8b86-4d01-b42d-00c04fc964ff")}).dump());
    ASSERT_EQ(doc.entries.size(), 1u);
    EXPECT_EQ(doc.entries[0].title, "");
    EXPECT_FALSE(doc.entries[0].favorite);
    EXPECT_TRUE(doc.tombstones.empty());
    EXPECT_TRUE(doc.preferences.is_object());
}

TEST(VaultDocument, UnknownFieldsArePreserved) {
    // A newer PhylaxBox added fields; an older one must not drop them on save.
    json entry = minimal_entry("6f9619ff-8b86-4d01-b42d-00c04fc964ff");
    entry["passkey"] = {{"credentialId", "abc"}};
    json root = doc_with_entries({entry});
    root["folders"] = json::array({"Work"});

    const auto doc = vault_document::from_json(root.dump());
    const auto saved = json::parse(doc.to_json());
    EXPECT_EQ(saved.at("folders"), json::array({"Work"}));
    EXPECT_EQ(saved.at("entries")[0].at("passkey").at("credentialId"), "abc");
}

TEST(VaultDocument, NewerSchemaIsUnsupported) {
    EXPECT_EQ(format_error(R"({"schema":2,"entries":[]})"), ErrorCodes::UNSUPPORTED_VERSION);
}

TEST(VaultDocument, InvalidDocuments) {
    const std::string id = "6f9619ff-8b86-4d01-b42d-00c04fc964ff";
    const int invalid = ErrorCodes::INVALID_FORMAT;
    EXPECT_EQ(format_error("not json"), invalid);
    EXPECT_EQ(format_error("[]"), invalid);
    EXPECT_EQ(format_error(R"({"entries":[]})"), invalid);           // no schema
    EXPECT_EQ(format_error(R"({"schema":1})"), invalid);             // no entries
    EXPECT_EQ(format_error(R"({"schema":0,"entries":[]})"), invalid);

    // Each case must fail on the field it modifies.
    auto with = [&](const char* key, json value) {
        json e = minimal_entry(id);
        if (value.is_null()) e.erase(key); else e[key] = value;
        return format_error(doc_with_entries({e}).dump(), key);
    };
    EXPECT_EQ(with("id", "6F9619FF-8B86-4D01-B42D-00C04FC964FF"), invalid); // not lowercase
    EXPECT_EQ(with("id", "not-a-uuid"), invalid);
    EXPECT_EQ(with("id", nullptr), invalid);
    EXPECT_EQ(with("createdAt", "2026-11-17 12:00:00"), invalid);
    EXPECT_EQ(with("updatedAt", "2026-11-17T12:00:00+01:00"), invalid); // must be UTC
    EXPECT_EQ(with("updatedAt", "2026-13-17T12:00:00Z"), invalid);
    EXPECT_EQ(with("revision", 0), invalid);
    EXPECT_EQ(with("revision", -1), invalid);
    EXPECT_EQ(with("revision", "1"), invalid);
    EXPECT_EQ(with("deviceId", "laptop"), invalid);
    EXPECT_EQ(with("urls", "https://example.com"), invalid);
    EXPECT_EQ(with("tags", json::array({1})), invalid);
    EXPECT_EQ(with("favorite", "yes"), invalid);
    EXPECT_EQ(with("password", 1234), invalid);

    EXPECT_EQ(format_error(doc_with_entries({minimal_entry(id), minimal_entry(id)}).dump(),
                           "duplicate id"),
              invalid);

    json root = doc_with_entries({minimal_entry(id)});
    root["tombstones"] = json::array();
    root["tombstones"].push_back(
        {{"id", id}, {"deletedAt", kTime}, {"revision", 2}, {"deviceId", kDevice}});
    EXPECT_EQ(format_error(root.dump(), "also live"), invalid); // both live and deleted
}

TEST(VaultDocument, TimestampsAcceptSecondsOrMilliseconds) {
    EXPECT_TRUE(is_utc_timestamp("2026-11-17T12:34:56Z"));
    EXPECT_TRUE(is_utc_timestamp("2026-11-17T12:34:56.789Z"));
    EXPECT_FALSE(is_utc_timestamp("2026-11-17T12:34:56.7Z"));
    EXPECT_FALSE(is_utc_timestamp("2026-11-17T24:00:00Z"));
}

TEST(VaultDocument, GeneratedIdsAndTimes) {
    std::set<std::string> ids;
    for (int i = 0; i < 1000; ++i) {
        const auto id = new_uuid();
        ASSERT_TRUE(is_canonical_uuid(id)) << id;
        EXPECT_EQ(id[14], '4');                                  // version 4
        EXPECT_NE(std::string("89ab").find(id[19]), std::string::npos); // RFC 4122 variant
        ids.insert(id);
    }
    EXPECT_EQ(ids.size(), 1000u);
    EXPECT_TRUE(is_utc_timestamp(utc_now())) << utc_now();
}

TEST(VaultDocument, ToJsonValidates) {
    vault_document doc;
    doc.entries.push_back(make_entry("bad id"));
    EXPECT_THROW(doc.to_json(), vault_format_exception);

    vault_document invalid_utf8;
    invalid_utf8.entries.push_back(make_entry(new_uuid()));
    invalid_utf8.entries[0].password = "\xFF\xFE";
    EXPECT_THROW(invalid_utf8.to_json(), vault_format_exception);
}

TEST(VaultDocument, TenThousandEntries) {
    vault_document doc;
    for (int i = 0; i < 10000; ++i) doc.entries.push_back(make_entry(new_uuid()));
    const auto parsed = vault_document::from_json(doc.to_json());
    EXPECT_EQ(parsed.entries.size(), 10000u);
}

TEST(VaultDocument, UtcSecondsMatchesPythonCalendarTimegm) {
    // Reference values from Python: calendar.timegm(datetime.fromisoformat(s).timetuple())
    EXPECT_EQ(utc_seconds("1970-01-01T00:00:00Z"), 0);
    EXPECT_EQ(utc_seconds("2000-03-01T00:00:00Z"), 951868800);
    EXPECT_EQ(utc_seconds("2024-02-29T23:59:59Z"), 1709251199);         // leap day
    EXPECT_EQ(utc_seconds("2026-11-17T12:34:56.789Z"), 1794918896);     // milliseconds ignored
    EXPECT_FALSE(utc_seconds("2023-02-29T00:00:00Z").has_value());      // not a leap year
    EXPECT_FALSE(utc_seconds("2026-04-31T00:00:00Z").has_value());
    EXPECT_FALSE(utc_seconds("not a date").has_value());
}

TEST(VaultDocument, PurgeTombstonesOlderThan180Days) {
    auto make = [](const char* deleted_at) {
        tombstone t;
        t.id = new_uuid();
        t.deleted_at = deleted_at;
        t.device_id = kDevice;
        return t;
    };
    vault_document doc;
    doc.entries.push_back(make_entry(new_uuid()));
    doc.tombstones = {make("2026-05-20T00:00:00Z"),   // 181 days before "now": purged
                      make("2026-05-21T00:00:00Z"),   // exactly 180 days: kept
                      make("2026-05-22T00:00:00Z"),   // 179 days: kept
                      make("2026-11-16T23:59:59.999Z")};
    EXPECT_EQ(doc.purge_tombstones("2026-11-17T00:00:00Z"), 1u);
    ASSERT_EQ(doc.tombstones.size(), 3u);
    EXPECT_EQ(doc.tombstones[0].deleted_at, "2026-05-21T00:00:00Z");
    EXPECT_EQ(doc.entries.size(), 1u); // live entries are never touched

    EXPECT_EQ(doc.purge_tombstones("2026-11-17T00:00:00Z", std::chrono::hours(24)), 2u);
    EXPECT_THROW(doc.purge_tombstones("yesterday"), std::invalid_argument);
}
