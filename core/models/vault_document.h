#ifndef PB_VAULT_DOCUMENT_H_
#define PB_VAULT_DOCUMENT_H_

#include "crypto/secure_allocator.h"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Logical vault content (spec §4.5), serialized as JSON inside the container.
// Normative description: docs/vault-format/README.md, "Vault content (schema 1)".
//
// Memory (spec §12.2): fields that reveal the user's secrets or accounts use
// secure_string / secure_vector / secure_json, whose memory is wiped when
// freed. Identifiers and timestamps are plain std::string. Known gap: the
// JSON parser's internal token buffer (nlohmann lexer) uses the default
// allocator and is freed without wiping.
namespace pb {

struct vault_entry {
    std::string id; // lowercase canonical UUID, stable for the entry's life
    secure_string title;
    secure_string username;
    secure_string password;
    secure_vector<secure_string> urls;
    secure_string application; // optional desktop application identifier
    secure_string notes;
    secure_vector<secure_string> tags;
    bool favorite = false;
    std::string created_at; // RFC 3339 UTC, e.g. 2026-11-17T12:34:56.789Z
    std::string updated_at;
    std::uint64_t revision = 1; // incremented on every change of this entry
    std::string device_id;      // device that made the latest change

    // Fields written by newer versions, preserved verbatim on save.
    secure_json extra = secure_json::object();
};

// What remains of a deleted entry: no secrets, only what synchronization
// needs to stop the entry from reappearing (spec §6.6).
struct tombstone {
    std::string id;
    std::string deleted_at;
    std::uint64_t revision = 1; // the entry's revision at deletion, +1
    std::string device_id;
    secure_json extra = secure_json::object();
};

struct vault_document {
    static constexpr int SCHEMA = 1;
    static constexpr std::size_t MAX_ENTRIES = 100000;
    // Deletion records older than this are dropped on save (ADR 0002). A
    // device that stays offline longer may bring such entries back.
    static constexpr std::chrono::hours TOMBSTONE_RETENTION{24 * 180};

    secure_vector<vault_entry> entries;
    std::vector<tombstone> tombstones;
    secure_json preferences = secure_json::object(); // vault-level settings
    secure_json extra = secure_json::object();       // unknown top-level fields

    // Parses and validates (spec §4.1 step 2). Throws vault_format_exception,
    // or with UNSUPPORTED_VERSION when written by a newer schema.
    static vault_document from_json(std::string_view text);

    // Validates, then serializes. Throws vault_format_exception if invalid.
    secure_string to_json() const;

    // Throws vault_format_exception describing the first problem found.
    void validate() const;

    const vault_entry* find(std::string_view id) const;

    // Removes tombstones deleted more than `retention` before `now`
    // (RFC 3339 UTC). Returns how many were removed.
    std::size_t purge_tombstones(std::string_view now,
                                 std::chrono::seconds retention = TOMBSTONE_RETENTION);
};

// Random (version 4) UUID in lowercase canonical form.
std::string new_uuid();

// Current time as RFC 3339 UTC with milliseconds (same shape as JS toISOString()).
std::string utc_now();

bool is_canonical_uuid(std::string_view s);
bool is_utc_timestamp(std::string_view s);

// Seconds since the Unix epoch for an RFC 3339 UTC timestamp (as accepted by
// is_utc_timestamp, milliseconds ignored); nullopt if invalid (e.g. Feb 30).
std::optional<std::int64_t> utc_seconds(std::string_view s);

} // namespace pb

#endif // PB_VAULT_DOCUMENT_H_
