#include "models/vault_document.h"

#include "crypto/crypto.h"
#include "models/pbexceptions.h"

#include <array>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <unordered_set>

namespace pb {

using json = nlohmann::json;

namespace {

const char* const ENTRY_KEYS[] = {"id",    "title",     "username",  "password",
                                  "urls",  "application", "notes",   "tags",
                                  "favorite", "createdAt", "updatedAt", "revision",
                                  "deviceId"};
const char* const TOMBSTONE_KEYS[] = {"id", "deletedAt", "revision", "deviceId"};
const char* const TOP_KEYS[] = {"schema", "entries", "tombstones", "preferences"};

[[noreturn]] void bad(const std::string& what) { throw vault_format_exception(what); }

template <std::size_t N>
json unknown_fields(const json& obj, const char* const (&known)[N]) {
    json extra = json::object();
    for (auto it = obj.begin(); it != obj.end(); ++it) {
        bool is_known = false;
        for (const char* k : known) is_known = is_known || it.key() == k;
        if (!is_known) extra[it.key()] = it.value();
    }
    return extra;
}

std::string req_string(const json& obj, const char* key, const std::string& where) {
    const auto it = obj.find(key);
    if (it == obj.end() || !it->is_string()) bad(where + ": '" + key + "' must be a string");
    return it->get<std::string>();
}

std::string opt_string(const json& obj, const char* key, const std::string& where) {
    const auto it = obj.find(key);
    if (it == obj.end() || it->is_null()) return {};
    if (!it->is_string()) bad(where + ": '" + key + "' must be a string");
    return it->get<std::string>();
}

std::vector<std::string> opt_string_array(const json& obj, const char* key,
                                          const std::string& where) {
    std::vector<std::string> out;
    const auto it = obj.find(key);
    if (it == obj.end() || it->is_null()) return out;
    if (!it->is_array()) bad(where + ": '" + key + "' must be an array of strings");
    for (const auto& v : *it) {
        if (!v.is_string()) bad(where + ": '" + key + "' must be an array of strings");
        out.push_back(v.get<std::string>());
    }
    return out;
}

std::uint64_t req_revision(const json& obj, const std::string& where) {
    const auto it = obj.find("revision");
    if (it == obj.end() || !it->is_number_unsigned() || it->get<std::uint64_t>() < 1) {
        bad(where + ": 'revision' must be an integer >= 1");
    }
    return it->get<std::uint64_t>();
}

void merge_extra(json& out, const json& extra) {
    for (auto it = extra.begin(); it != extra.end(); ++it) {
        if (!out.contains(it.key())) out[it.key()] = it.value();
    }
}

} // namespace

bool is_canonical_uuid(std::string_view s) {
    if (s.size() != 36) return false;
    for (std::size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-') return false;
        } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return false;
        }
    }
    return true;
}

bool is_utc_timestamp(std::string_view s) {
    // YYYY-MM-DDTHH:MM:SSZ or YYYY-MM-DDTHH:MM:SS.sssZ
    static const char* shape_s = "dddd-dd-ddTdd:dd:ddZ";
    static const char* shape_ms = "dddd-dd-ddTdd:dd:dd.dddZ";
    const char* shape = s.size() == 20 ? shape_s : s.size() == 24 ? shape_ms : nullptr;
    if (!shape) return false;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (shape[i] == 'd') {
            if (s[i] < '0' || s[i] > '9') return false;
        } else if (s[i] != shape[i]) {
            return false;
        }
    }
    const int month = (s[5] - '0') * 10 + (s[6] - '0');
    const int day = (s[8] - '0') * 10 + (s[9] - '0');
    const int hour = (s[11] - '0') * 10 + (s[12] - '0');
    const int minute = (s[14] - '0') * 10 + (s[15] - '0');
    const int second = (s[17] - '0') * 10 + (s[18] - '0');
    return month >= 1 && month <= 12 && day >= 1 && day <= 31 && hour <= 23 && minute <= 59 &&
           second <= 60;
}

std::string new_uuid() {
    std::array<std::uint8_t, 16> b{};
    crypto::random_bytes(b.data(), b.size());
    b[6] = static_cast<std::uint8_t>((b[6] & 0x0F) | 0x40); // version 4
    b[8] = static_cast<std::uint8_t>((b[8] & 0x3F) | 0x80); // RFC 4122 variant
    char out[37];
    std::snprintf(out, sizeof out,
                  "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", b[0],
                  b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13],
                  b[14], b[15]);
    return out;
}

std::string utc_now() {
    using namespace std::chrono;
    const auto now = system_clock::now();
    const std::time_t t = system_clock::to_time_t(now);
    const auto ms = duration_cast<milliseconds>(now.time_since_epoch()).count() % 1000;
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char out[32];
    std::snprintf(out, sizeof out, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", tm.tm_year + 1900,
                  tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
                  static_cast<int>(ms));
    return out;
}

vault_document vault_document::from_json(std::string_view text) {
    json root;
    try {
        root = json::parse(text);
    } catch (const json::parse_error& e) {
        bad(std::string("vault content is not valid JSON: ") + e.what());
    }
    if (!root.is_object()) bad("vault content must be a JSON object");

    const auto schema = root.find("schema");
    if (schema == root.end() || !schema->is_number_integer()) bad("'schema' is missing");
    if (schema->get<std::int64_t>() > SCHEMA) {
        throw vault_format_exception("vault written by a newer PhylaxBox (schema " +
                                         std::to_string(schema->get<std::int64_t>()) + ")",
                                     ErrorCodes::UNSUPPORTED_VERSION);
    }
    if (schema->get<std::int64_t>() < 1) bad("invalid 'schema'");

    vault_document doc;
    doc.extra = unknown_fields(root, TOP_KEYS);

    const auto entries = root.find("entries");
    if (entries == root.end() || !entries->is_array()) bad("'entries' must be an array");
    if (entries->size() > MAX_ENTRIES) bad("too many entries");
    for (std::size_t i = 0; i < entries->size(); ++i) {
        const json& o = (*entries)[i];
        const std::string where = "entries[" + std::to_string(i) + "]";
        if (!o.is_object()) bad(where + " must be an object");
        vault_entry e;
        e.id = req_string(o, "id", where);
        e.title = opt_string(o, "title", where);
        e.username = opt_string(o, "username", where);
        e.password = opt_string(o, "password", where);
        e.urls = opt_string_array(o, "urls", where);
        e.application = opt_string(o, "application", where);
        e.notes = opt_string(o, "notes", where);
        e.tags = opt_string_array(o, "tags", where);
        if (const auto f = o.find("favorite"); f != o.end() && !f->is_null()) {
            if (!f->is_boolean()) bad(where + ": 'favorite' must be a boolean");
            e.favorite = f->get<bool>();
        }
        e.created_at = req_string(o, "createdAt", where);
        e.updated_at = req_string(o, "updatedAt", where);
        e.revision = req_revision(o, where);
        e.device_id = req_string(o, "deviceId", where);
        e.extra = unknown_fields(o, ENTRY_KEYS);
        doc.entries.push_back(std::move(e));
    }

    if (const auto ts = root.find("tombstones"); ts != root.end() && !ts->is_null()) {
        if (!ts->is_array()) bad("'tombstones' must be an array");
        if (ts->size() > MAX_ENTRIES) bad("too many tombstones");
        for (std::size_t i = 0; i < ts->size(); ++i) {
            const json& o = (*ts)[i];
            const std::string where = "tombstones[" + std::to_string(i) + "]";
            if (!o.is_object()) bad(where + " must be an object");
            tombstone t;
            t.id = req_string(o, "id", where);
            t.deleted_at = req_string(o, "deletedAt", where);
            t.revision = req_revision(o, where);
            t.device_id = req_string(o, "deviceId", where);
            t.extra = unknown_fields(o, TOMBSTONE_KEYS);
            doc.tombstones.push_back(std::move(t));
        }
    }

    if (const auto prefs = root.find("preferences"); prefs != root.end() && !prefs->is_null()) {
        if (!prefs->is_object()) bad("'preferences' must be an object");
        doc.preferences = *prefs;
    }

    doc.validate();
    return doc;
}

void vault_document::validate() const {
    if (entries.size() > MAX_ENTRIES || tombstones.size() > MAX_ENTRIES) bad("too many entries");
    std::unordered_set<std::string_view> ids;
    for (std::size_t i = 0; i < entries.size(); ++i) {
        const auto& e = entries[i];
        const std::string where = "entries[" + std::to_string(i) + "]";
        if (!is_canonical_uuid(e.id)) bad(where + ": 'id' must be a lowercase UUID");
        if (!ids.insert(e.id).second) bad(where + ": duplicate id " + e.id);
        if (!is_utc_timestamp(e.created_at)) bad(where + ": 'createdAt' must be RFC 3339 UTC");
        if (!is_utc_timestamp(e.updated_at)) bad(where + ": 'updatedAt' must be RFC 3339 UTC");
        if (e.revision < 1) bad(where + ": 'revision' must be >= 1");
        if (!is_canonical_uuid(e.device_id)) bad(where + ": 'deviceId' must be a lowercase UUID");
        if (!e.extra.is_object()) bad(where + ": internal extra fields must be an object");
    }
    for (std::size_t i = 0; i < tombstones.size(); ++i) {
        const auto& t = tombstones[i];
        const std::string where = "tombstones[" + std::to_string(i) + "]";
        if (!is_canonical_uuid(t.id)) bad(where + ": 'id' must be a lowercase UUID");
        if (!ids.insert(t.id).second) bad(where + ": id " + t.id + " is also live or duplicated");
        if (!is_utc_timestamp(t.deleted_at)) bad(where + ": 'deletedAt' must be RFC 3339 UTC");
        if (t.revision < 1) bad(where + ": 'revision' must be >= 1");
        if (!is_canonical_uuid(t.device_id)) bad(where + ": 'deviceId' must be a lowercase UUID");
    }
    if (!preferences.is_object()) bad("'preferences' must be an object");
}

std::string vault_document::to_json() const {
    validate();
    json root = json::object();
    root["schema"] = SCHEMA;
    json arr = json::array();
    for (const auto& e : entries) {
        json o = {{"id", e.id},
                  {"title", e.title},
                  {"username", e.username},
                  {"password", e.password},
                  {"urls", e.urls},
                  {"application", e.application},
                  {"notes", e.notes},
                  {"tags", e.tags},
                  {"favorite", e.favorite},
                  {"createdAt", e.created_at},
                  {"updatedAt", e.updated_at},
                  {"revision", e.revision},
                  {"deviceId", e.device_id}};
        merge_extra(o, e.extra);
        arr.push_back(std::move(o));
    }
    root["entries"] = std::move(arr);
    json ts = json::array();
    for (const auto& t : tombstones) {
        json o = {{"id", t.id},
                  {"deletedAt", t.deleted_at},
                  {"revision", t.revision},
                  {"deviceId", t.device_id}};
        merge_extra(o, t.extra);
        ts.push_back(std::move(o));
    }
    root["tombstones"] = std::move(ts);
    root["preferences"] = preferences;
    merge_extra(root, extra);
    // ensure_ascii=false keeps UTF-8 as is; invalid UTF-8 throws (caught below).
    try {
        return root.dump();
    } catch (const json::type_error& e) {
        bad(std::string("vault content is not valid UTF-8: ") + e.what());
    }
}

const vault_entry* vault_document::find(std::string_view id) const {
    for (const auto& e : entries) {
        if (e.id == id) return &e;
    }
    return nullptr;
}

} // namespace pb
