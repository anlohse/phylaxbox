#ifndef PB_VAULT_DOCUMENT_H_
#define PB_VAULT_DOCUMENT_H_

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

// Logical vault content (spec §4.5), serialized as JSON inside the container.
// Normative description: docs/vault-format/README.md, "Vault content (schema 1)".
namespace pb {

struct vault_entry {
    std::string id; // lowercase canonical UUID, stable for the entry's life
    std::string title;
    std::string username;
    std::string password;
    std::vector<std::string> urls;
    std::string application; // optional desktop application identifier
    std::string notes;
    std::vector<std::string> tags;
    bool favorite = false;
    std::string created_at; // RFC 3339 UTC, e.g. 2026-11-17T12:34:56.789Z
    std::string updated_at;
    std::uint64_t revision = 1; // incremented on every change of this entry
    std::string device_id;      // device that made the latest change

    // Fields written by newer versions, preserved verbatim on save.
    nlohmann::json extra = nlohmann::json::object();
};

// What remains of a deleted entry: no secrets, only what synchronization
// needs to stop the entry from reappearing (spec §6.6).
struct tombstone {
    std::string id;
    std::string deleted_at;
    std::uint64_t revision = 1; // the entry's revision at deletion, +1
    std::string device_id;
    nlohmann::json extra = nlohmann::json::object();
};

struct vault_document {
    static constexpr int SCHEMA = 1;
    static constexpr std::size_t MAX_ENTRIES = 100000;

    std::vector<vault_entry> entries;
    std::vector<tombstone> tombstones;
    nlohmann::json preferences = nlohmann::json::object(); // vault-level settings
    nlohmann::json extra = nlohmann::json::object();       // unknown top-level fields

    // Parses and validates (spec §4.1 step 2). Throws vault_format_exception,
    // or with UNSUPPORTED_VERSION when written by a newer schema.
    static vault_document from_json(std::string_view text);

    // Validates, then serializes. Throws vault_format_exception if invalid.
    std::string to_json() const;

    // Throws vault_format_exception describing the first problem found.
    void validate() const;

    const vault_entry* find(std::string_view id) const;
};

// Random (version 4) UUID in lowercase canonical form.
std::string new_uuid();

// Current time as RFC 3339 UTC with milliseconds (same shape as JS toISOString()).
std::string utc_now();

bool is_canonical_uuid(std::string_view s);
bool is_utc_timestamp(std::string_view s);

} // namespace pb

#endif // PB_VAULT_DOCUMENT_H_
