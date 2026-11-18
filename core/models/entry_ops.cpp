#include "models/entry_ops.h"

#include "models/pbexceptions.h"
#include "storage/vault_store.h"

#include <algorithm>
#include <string>

namespace pb {

namespace {

[[noreturn]] void invalid(const std::string& why) {
    throw pbexception(ErrorCodes::INVALID_ENTRY, why);
}

bool is_space(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

void trim(secure_string& s) {
    std::size_t begin = 0;
    while (begin < s.size() && is_space(s[begin])) ++begin;
    std::size_t end = s.size();
    while (end > begin && is_space(s[end - 1])) --end;
    if (begin > 0 || end < s.size()) s = secure_string(s.data() + begin, end - begin);
}

void check_length(const secure_string& s, std::size_t limit, const char* field) {
    if (vault_store::password_length(view(s)) > limit) {
        invalid(std::string(field) + " is too long (max " + std::to_string(limit) + ")");
    }
}

void check_utf8(const secure_string& s, const char* field) {
    // Rejects malformed sequences so to_json() never fails later.
    std::size_t i = 0;
    const auto* p = reinterpret_cast<const unsigned char*>(s.data());
    while (i < s.size()) {
        const unsigned char c = p[i];
        std::size_t n = c < 0x80 ? 1 : (c >> 5) == 0x6 ? 2 : (c >> 4) == 0xE ? 3 : (c >> 3) == 0x1E ? 4 : 0;
        if (n == 0 || i + n > s.size()) invalid(std::string(field) + " is not valid UTF-8");
        for (std::size_t k = 1; k < n; ++k) {
            if ((p[i + k] & 0xC0) != 0x80) invalid(std::string(field) + " is not valid UTF-8");
        }
        i += n;
    }
}

void clean_list(secure_vector<secure_string>& items, bool dedupe) {
    secure_vector<secure_string> out;
    for (auto& item : items) {
        trim(item);
        if (item.empty()) continue;
        if (dedupe && std::find(out.begin(), out.end(), item) != out.end()) continue;
        out.push_back(std::move(item));
    }
    items = std::move(out);
}

vault_entry* find_mutable(vault_document& doc, std::string_view id) {
    for (auto& e : doc.entries) {
        if (e.id == id) return &e;
    }
    return nullptr;
}

vault_entry& require_entry(vault_document& doc, std::string_view id) {
    vault_entry* e = find_mutable(doc, id);
    if (!e) throw pbexception(ErrorCodes::ENTRY_NOT_FOUND, "no entry with id " + std::string(id));
    return *e;
}

void assign(vault_entry& e, entry_fields&& f) {
    e.title = std::move(f.title);
    e.username = std::move(f.username);
    e.password = std::move(f.password);
    e.urls = std::move(f.urls);
    e.application = std::move(f.application);
    e.notes = std::move(f.notes);
    e.tags = std::move(f.tags);
    e.favorite = f.favorite;
}

void touch(vault_entry& e, std::string_view device_id, std::string_view now) {
    ++e.revision;
    e.updated_at = std::string(now);
    e.device_id = std::string(device_id);
}

} // namespace

void normalize_and_validate(entry_fields& f) {
    trim(f.title);
    trim(f.username);
    trim(f.application);
    clean_list(f.urls, false);
    clean_list(f.tags, true);

    if (f.title.empty()) invalid("title is required");
    check_length(f.title, entry_limits::TITLE, "title");
    check_length(f.username, entry_limits::USERNAME, "username");
    check_length(f.password, entry_limits::PASSWORD, "password");
    check_length(f.application, entry_limits::APPLICATION, "application");
    check_length(f.notes, entry_limits::NOTES, "notes");
    if (f.urls.size() > entry_limits::URLS) invalid("too many URLs");
    for (const auto& u : f.urls) check_length(u, entry_limits::URL, "URL");
    if (f.tags.size() > entry_limits::TAGS) invalid("too many tags");
    for (const auto& t : f.tags) check_length(t, entry_limits::TAG, "tag");

    for (const auto* s : {&f.title, &f.username, &f.password, &f.application, &f.notes}) {
        check_utf8(*s, "field");
    }
    for (const auto& u : f.urls) check_utf8(u, "URL");
    for (const auto& t : f.tags) check_utf8(t, "tag");
}

std::string add_entry(vault_document& doc, entry_fields fields, std::string_view device_id,
                      std::string_view now) {
    normalize_and_validate(fields);
    if (doc.entries.size() >= vault_document::MAX_ENTRIES) invalid("the vault is full");
    vault_entry e;
    e.id = new_uuid();
    assign(e, std::move(fields));
    e.created_at = std::string(now);
    e.updated_at = std::string(now);
    e.revision = 1;
    e.device_id = std::string(device_id);
    doc.entries.push_back(std::move(e));
    return doc.entries.back().id;
}

void update_entry(vault_document& doc, std::string_view id, entry_fields fields,
                  std::string_view device_id, std::string_view now) {
    vault_entry& e = require_entry(doc, id);
    normalize_and_validate(fields);
    assign(e, std::move(fields));
    touch(e, device_id, now);
}

void set_favorite(vault_document& doc, std::string_view id, bool favorite,
                  std::string_view device_id, std::string_view now) {
    vault_entry& e = require_entry(doc, id);
    if (e.favorite == favorite) return;
    e.favorite = favorite;
    touch(e, device_id, now);
}

void delete_entry(vault_document& doc, std::string_view id, std::string_view device_id,
                  std::string_view now) {
    const auto it = std::find_if(doc.entries.begin(), doc.entries.end(),
                                 [&](const vault_entry& e) { return e.id == id; });
    if (it == doc.entries.end()) {
        throw pbexception(ErrorCodes::ENTRY_NOT_FOUND, "no entry with id " + std::string(id));
    }
    tombstone t;
    t.id = it->id;
    t.deleted_at = std::string(now);
    t.revision = it->revision + 1;
    t.device_id = std::string(device_id);
    doc.entries.erase(it); // zeroing allocator wipes the entry's secrets
    doc.tombstones.push_back(std::move(t));
}

} // namespace pb
