#ifndef PB_ENTRY_OPS_H_
#define PB_ENTRY_OPS_H_

#include "models/vault_document.h"

#include <string>
#include <string_view>

// Editing operations on the vault content. They keep the synchronization
// metadata consistent (spec §4.5, §6.6): stable ids, per-entry revisions,
// UTC timestamps, the device that made the change, and tombstones for
// deletions.
namespace pb {

// What the user edits. Ids, timestamps and revisions are managed here.
struct entry_fields {
    secure_string title;
    secure_string username;
    secure_string password;
    secure_vector<secure_string> urls;
    secure_string application;
    secure_string notes;
    secure_vector<secure_string> tags;
    bool favorite = false;
};

struct entry_limits {
    static constexpr std::size_t TITLE = 1024;    // code points
    static constexpr std::size_t USERNAME = 1024;
    static constexpr std::size_t PASSWORD = 4096;
    static constexpr std::size_t URL = 2048;
    static constexpr std::size_t URLS = 50;
    static constexpr std::size_t APPLICATION = 1024;
    static constexpr std::size_t NOTES = 65536;
    static constexpr std::size_t TAG = 100;
    static constexpr std::size_t TAGS = 50;
};

// Trims surrounding whitespace from single-line fields, drops empty URLs and
// tags, removes duplicate tags, then checks the limits. A title is required.
// Throws pbexception(INVALID_ENTRY) describing the problem.
void normalize_and_validate(entry_fields& fields);

// Returns the new entry's id.
std::string add_entry(vault_document& doc, entry_fields fields, std::string_view device_id,
                      std::string_view now);

// Replaces the editable fields; bumps the revision. Throws
// pbexception(ENTRY_NOT_FOUND) / pbexception(INVALID_ENTRY).
void update_entry(vault_document& doc, std::string_view id, entry_fields fields,
                  std::string_view device_id, std::string_view now);

void set_favorite(vault_document& doc, std::string_view id, bool favorite,
                  std::string_view device_id, std::string_view now);

// Removes the entry and records a tombstone (no secrets kept).
void delete_entry(vault_document& doc, std::string_view id, std::string_view device_id,
                  std::string_view now);

} // namespace pb

#endif // PB_ENTRY_OPS_H_
