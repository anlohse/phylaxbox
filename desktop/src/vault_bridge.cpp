#include "vault_bridge.h"

#include "bridge_reply.h"

#include "crypto/passphrase_generator.h"
#include "crypto/password_generator.h"
#include "models/entry_ops.h"
#include "models/pbexceptions.h"
#include "models/vault_preferences.h"

#include <exception>
#include <functional>
#include <stdexcept>

#ifndef PB_VERSION_STRING
#define PB_VERSION_STRING "0.0.0-dev"
#endif

namespace pb::app {

namespace {

// English fallbacks; the UI shows its own translation of each `code`.
namespace msg {
const char* bad_request = "Invalid request.";
const char* internal = "Internal error. Nothing was saved.";
const char* wrong_password = "Wrong master password.";
const char* wrong_recovery = "Wrong recovery key for this vault.";
const char* invalid_recovery = "Invalid recovery key. Check that it was typed correctly.";
const char* no_recovery = "This vault has no recovery key.";
const char* weak_password = "The master password needs at least 8 characters.";
const char* exists = "A vault already exists at this location.";
const char* not_found = "No vault was found at this location.";
const char* io = "The vault file could not be read or written.";
const char* integrity = "The vault file is damaged or was modified.";
const char* newer = "This vault was created by a newer version of PhylaxBox.";
const char* invalid_file = "The file is not a valid PhylaxBox vault.";
const char* save_failed = "Saving could not be verified. The previous file was kept.";
const char* locked = "The vault is locked.";
const char* entry_not_found = "This item no longer exists.";
const char* title_required = "Enter a title.";
const char* invalid_entry = "A field is too long or contains invalid characters.";
const char* clipboard = "Could not copy to the clipboard.";
const char* generator = "Choose a length between 8 and 128 and at least one character type.";
const char* passphrase = "Choose between 4 and 20 words and a separator without letters.";
const char* bad_settings = "One of the settings is out of range.";
const char* backup_not_found = "That backup no longer exists.";
const char* dialog = "File dialogs are not available.";
} // namespace msg

enum class context { unlock, recover, other };

std::string from_exception(context ctx) {
    try {
        throw;
    } catch (const wrong_password_exception&) {
        return ctx == context::recover ? fail("wrong_recovery_key", msg::wrong_recovery)
                                       : fail("wrong_password", msg::wrong_password);
    } catch (const integrity_exception&) {
        return fail("corrupted", msg::integrity);
    } catch (const vault_format_exception& e) {
        if (e.errorcode() == ErrorCodes::UNSUPPORTED_VERSION) {
            return fail("unsupported_version", msg::newer);
        }
        return fail("invalid_file", msg::invalid_file);
    } catch (const ioexception& e) {
        if (e.errorcode() == ErrorCodes::FILE_NOT_FOUND) return fail("not_found", msg::not_found);
        return fail("io_error", msg::io);
    } catch (const pbexception& e) {
        switch (e.errorcode()) {
        case ErrorCodes::WEAK_PASSWORD: return fail("weak_password", msg::weak_password);
        case ErrorCodes::VAULT_EXISTS: return fail("vault_exists", msg::exists);
        case ErrorCodes::NO_RECOVERY_SLOT: return fail("no_recovery_key", msg::no_recovery);
        case ErrorCodes::INVALID_RECOVERY_KEY:
            return fail("invalid_recovery_key", msg::invalid_recovery);
        case ErrorCodes::SAVE_VERIFICATION_FAILED: return fail("save_failed", msg::save_failed);
        case ErrorCodes::VAULT_LOCKED: return fail("locked", msg::locked);
        case ErrorCodes::ENTRY_NOT_FOUND: return fail("entry_not_found", msg::entry_not_found);
        case ErrorCodes::INVALID_ENTRY:
            if (std::string(e.what()).find("title is required") != std::string::npos) {
                return fail("title_required", msg::title_required);
            }
            return fail("invalid_entry", msg::invalid_entry);
        default: return fail("internal_error", msg::internal);
        }
    } catch (const json::exception&) {
        return fail("bad_request", msg::bad_request);
    } catch (const std::invalid_argument&) {
        return fail("bad_request", msg::bad_request);
    } catch (...) {
        return fail("internal_error", msg::internal);
    }
}

// Parses the request and runs `body`; maps every failure to a reply.
std::string handle(const std::string& request, std::size_t expected_args, context ctx,
                   const std::function<std::string(json& args)>& body) {
    try {
        json args = json::parse(request);
        if (!args.is_array() || args.size() != expected_args) {
            return fail("bad_request", msg::bad_request);
        }
        return body(args);
    } catch (...) {
        return from_exception(ctx);
    }
}

[[noreturn]] void bad_argument() { throw std::invalid_argument("bad argument"); }

const secure_string& string_ref(const json& v) {
    if (!v.is_string()) bad_argument();
    return v.get_ref<const secure_string&>();
}

std::string plain_string(const json& v) {
    const auto& s = string_ref(v);
    return std::string(s.data(), s.size());
}

bool boolean(const json& v) {
    if (!v.is_boolean()) bad_argument();
    return v.get<bool>();
}

std::uint64_t unsigned_number(const json& v) {
    if (!v.is_number_unsigned()) bad_argument();
    return v.get<std::uint64_t>();
}

secure_string string_field(const json& obj, const char* key) {
    const auto it = obj.find(key);
    if (it == obj.end() || it->is_null()) return {};
    return string_ref(*it);
}

secure_vector<secure_string> list_field(const json& obj, const char* key) {
    secure_vector<secure_string> out;
    const auto it = obj.find(key);
    if (it == obj.end() || it->is_null()) return out;
    if (!it->is_array()) bad_argument();
    for (const auto& v : *it) out.push_back(string_ref(v));
    return out;
}

entry_fields fields_from(const json& obj) {
    if (!obj.is_object()) bad_argument();
    entry_fields f;
    f.title = string_field(obj, "title");
    f.username = string_field(obj, "username");
    f.password = string_field(obj, "password");
    f.urls = list_field(obj, "urls");
    f.application = string_field(obj, "application");
    f.notes = string_field(obj, "notes");
    f.tags = list_field(obj, "tags");
    if (const auto it = obj.find("favorite"); it != obj.end() && !it->is_null()) f.favorite = boolean(*it);
    return f;
}

json strings(const secure_vector<secure_string>& items) {
    json out = json::array();
    for (const auto& s : items) out.push_back(s);
    return out;
}

json summary(const vault_entry& e) {
    return {{"id", to_secure(e.id)},
            {"title", e.title},
            {"username", e.username},
            {"urls", strings(e.urls)},
            {"tags", strings(e.tags)},
            {"favorite", e.favorite},
            {"updatedAt", to_secure(e.updated_at)}};
}

const vault_entry& find_entry(const vault_document& doc, const std::string& id) {
    const vault_entry* e = doc.find(id);
    if (!e) throw pbexception(ErrorCodes::ENTRY_NOT_FOUND, "no entry " + id);
    return *e;
}

secure_string utf8_path(const std::filesystem::path& p) {
    const auto u8 = p.u8string();
    return secure_string(reinterpret_cast<const char*>(u8.data()), u8.size());
}

std::filesystem::path path_from_utf8(const std::string& s) {
    return std::filesystem::path(std::u8string(s.begin(), s.end()));
}

// Applies `change` to a copy of the document and saves; on any failure the
// document in memory is left as it was (nothing half-applied).
template <typename Change>
void mutate(vault_store& store, Change&& change) {
    vault_document before = store.document();
    try {
        change(store.document());
        store.save();
    } catch (...) {
        store.document() = std::move(before);
        throw;
    }
}

// Finds a backup by the file name the UI got from backups_list().
std::filesystem::path backup_by_name(const vault_store& store, const std::string& name) {
    for (const auto& b : store.backups()) {
        if (utf8_path(b.path.filename()) == to_secure(name)) return b.path;
    }
    throw pbexception(ErrorCodes::ENTRY_NOT_FOUND, "backup not found");
}

} // namespace

vault_bridge::vault_bridge(vault_store& store, std::string device_id,
                           std::filesystem::path settings_file, hooks h)
    : m_store(store), m_device_id(std::move(device_id)), m_settings_file(std::move(settings_file)),
      m_settings(device_settings::load(m_settings_file)), m_hooks(std::move(h)) {
    m_store.set_backup_retention(m_settings.backup_retention);
}

void vault_bridge::save_settings() { m_settings.save(m_settings_file); }

// --- session ---------------------------------------------------------------

std::string vault_bridge::status(const std::string& request) {
    return handle(request, 0, context::other, [&](json&) {
        json reply = {{"exists", m_store.exists()},
                      {"unlocked", m_store.is_unlocked()},
                      {"vaultPath", utf8_path(m_store.path())},
                      {"isDefaultPath", m_store.path() == vault_store::default_path()}};
        if (m_store.is_unlocked()) {
            reply["entries"] = m_store.document().entries.size();
            reply["hasRecoveryKey"] = m_store.container().has_recovery_key();
        }
        return ok(std::move(reply));
    });
}

std::string vault_bridge::create(const std::string& request) {
    return handle(request, 2, context::other, [&](json& args) {
        const auto& password = string_ref(args[0]);
        const auto key = m_store.create(view(password), boolean(args[1]));
        json reply = {{"recoveryKey", nullptr}};
        if (key) reply["recoveryKey"] = to_secure(key->to_text());
        return ok(std::move(reply));
    });
}

std::string vault_bridge::unlock(const std::string& request) {
    return handle(request, 1, context::unlock, [&](json& args) {
        const auto& password = string_ref(args[0]);
        if (password.empty()) return fail("empty_password", msg::wrong_password);
        m_store.unlock(view(password));
        return ok({{"entries", m_store.document().entries.size()}});
    });
}

std::string vault_bridge::recover(const std::string& request) {
    return handle(request, 2, context::recover, [&](json& args) {
        const auto& key_text = string_ref(args[0]);
        const auto& new_password = string_ref(args[1]);
        // Validate the new password before the (slower) unlock.
        if (vault_store::password_length(view(new_password)) < vault_store::MIN_PASSWORD_CHARS) {
            return fail("weak_password", msg::weak_password);
        }
        const recovery_key key = recovery_key::parse(view(key_text));
        m_store.unlock_with_recovery_key(key);
        m_store.change_password(view(new_password));
        return ok({{"entries", m_store.document().entries.size()}});
    });
}

std::string vault_bridge::lock(const std::string& request) {
    return handle(request, 0, context::other, [&](json&) {
        m_store.lock();
        if (m_hooks.on_lock) m_hooks.on_lock();
        return ok();
    });
}

bool vault_bridge::auto_lock(lock_event event) {
    if (!m_store.is_unlocked()) return false;
    const auto prefs = vault_preferences::from(m_store.document());
    const bool wanted = event == lock_event::session_locked ? prefs.lock_on_session_lock
                                                            : prefs.lock_on_minimize;
    if (!wanted) return false;
    m_store.lock();
    if (m_hooks.on_lock) m_hooks.on_lock();
    return true;
}

// --- vault file -------------------------------------------------------------

std::string vault_bridge::choose_vault(const std::string& request) {
    return handle(request, 3, context::other, [&](json& args) {
        const std::string mode = plain_string(args[0]);
        if (mode != "open" && mode != "create") bad_argument();
        if (!m_hooks.choose_file) return fail("dialog_unavailable", msg::dialog);
        file_dialog_request dialog;
        dialog.save = mode == "create";
        dialog.title = plain_string(args[1]);
        dialog.filter_name = plain_string(args[2]);
        dialog.suggested_name = "vault.phylaxbox";
        const auto chosen = m_hooks.choose_file(dialog);
        if (!chosen) return ok({{"cancelled", true}});

        if (m_store.is_unlocked()) {
            m_store.lock();
            if (m_hooks.on_lock) m_hooks.on_lock();
        }
        const std::filesystem::path path = path_from_utf8(*chosen);
        if (!path.is_absolute()) bad_argument();
        m_store.set_path(path);
        m_settings.vault_path = *chosen;
        save_settings();
        return ok({{"cancelled", false}, {"path", utf8_path(path)}, {"exists", m_store.exists()}});
    });
}

std::string vault_bridge::use_default_vault(const std::string& request) {
    return handle(request, 0, context::other, [&](json&) {
        if (m_store.is_unlocked()) {
            m_store.lock();
            if (m_hooks.on_lock) m_hooks.on_lock();
        }
        m_store.set_path(vault_store::default_path());
        m_settings.vault_path.clear();
        save_settings();
        return ok({{"path", utf8_path(m_store.path())}, {"exists", m_store.exists()}});
    });
}

// --- entries ----------------------------------------------------------------

std::string vault_bridge::list(const std::string& request) {
    return handle(request, 0, context::other, [&](json&) {
        json entries = json::array();
        for (const auto& e : m_store.document().entries) entries.push_back(summary(e));
        return ok({{"entries", std::move(entries)}});
    });
}

std::string vault_bridge::get(const std::string& request) {
    return handle(request, 1, context::other, [&](json& args) {
        const std::string id = plain_string(args[0]);
        const auto& e = find_entry(m_store.document(), id);
        json entry = summary(e);
        entry["application"] = e.application;
        entry["notes"] = e.notes;
        entry["createdAt"] = to_secure(e.created_at);
        entry["hasPassword"] = !e.password.empty();
        return ok({{"entry", std::move(entry)}});
    });
}

std::string vault_bridge::reveal(const std::string& request) {
    return handle(request, 1, context::other, [&](json& args) {
        const std::string id = plain_string(args[0]);
        const auto& e = find_entry(m_store.document(), id);
        return ok({{"password", e.password}});
    });
}

std::string vault_bridge::add(const std::string& request) {
    return handle(request, 1, context::other, [&](json& args) {
        entry_fields fields = fields_from(args[0]);
        std::string id;
        mutate(m_store, [&](vault_document& doc) {
            id = add_entry(doc, std::move(fields), m_device_id, utc_now());
        });
        return ok({{"id", to_secure(id)}});
    });
}

std::string vault_bridge::update(const std::string& request) {
    return handle(request, 2, context::other, [&](json& args) {
        const std::string id = plain_string(args[0]);
        entry_fields fields = fields_from(args[1]);
        mutate(m_store, [&](vault_document& doc) {
            update_entry(doc, id, std::move(fields), m_device_id, utc_now());
        });
        return ok();
    });
}

std::string vault_bridge::remove(const std::string& request) {
    return handle(request, 1, context::other, [&](json& args) {
        const std::string id = plain_string(args[0]);
        mutate(m_store, [&](vault_document& doc) { delete_entry(doc, id, m_device_id, utc_now()); });
        return ok();
    });
}

std::string vault_bridge::favorite(const std::string& request) {
    return handle(request, 2, context::other, [&](json& args) {
        const std::string id = plain_string(args[0]);
        const bool value = boolean(args[1]);
        mutate(m_store, [&](vault_document& doc) {
            set_favorite(doc, id, value, m_device_id, utc_now());
        });
        return ok();
    });
}

std::string vault_bridge::copy(const std::string& request) {
    return handle(request, 2, context::other, [&](json& args) {
        const std::string id = plain_string(args[0]);
        const auto& e = find_entry(m_store.document(), id);
        const std::string field = plain_string(args[1]);
        secure_string text;
        if (field == "password") text = e.password;
        else if (field == "username") text = e.username;
        else bad_argument();
        const std::chrono::seconds clear_after(
            vault_preferences::from(m_store.document()).clipboard_clear_seconds);
        if (!m_hooks.copy_to_clipboard || !m_hooks.copy_to_clipboard(std::move(text), clear_after)) {
            return fail("clipboard_error", msg::clipboard);
        }
        return ok({{"clearsIn", clear_after.count()}});
    });
}

// --- settings ---------------------------------------------------------------

std::string vault_bridge::settings_get(const std::string& request) {
    return handle(request, 0, context::other, [&](json&) {
        json reply = {{"device",
                       {{"theme", to_secure(m_settings.theme)},
                        {"language", to_secure(m_settings.language)},
                        {"backupRetention", m_settings.backup_retention}}}};
        if (m_store.is_unlocked()) {
            const auto p = vault_preferences::from(m_store.document());
            reply["vault"] = {{"autoLockMinutes", p.auto_lock_minutes},
                              {"clipboardClearSeconds", p.clipboard_clear_seconds},
                              {"lockOnMinimize", p.lock_on_minimize},
                              {"lockOnSessionLock", p.lock_on_session_lock}};
        }
        return ok(std::move(reply));
    });
}

std::string vault_bridge::settings_set_device(const std::string& request) {
    return handle(request, 1, context::other, [&](json& args) {
        const json& o = args[0];
        if (!o.is_object()) bad_argument();
        device_settings next = m_settings;
        if (const auto it = o.find("theme"); it != o.end()) next.theme = plain_string(*it);
        if (const auto it = o.find("language"); it != o.end()) next.language = plain_string(*it);
        if (const auto it = o.find("backupRetention"); it != o.end()) {
            next.backup_retention = static_cast<std::size_t>(unsigned_number(*it));
        }
        try {
            next.validate();
        } catch (const std::invalid_argument&) {
            return fail("bad_settings", msg::bad_settings);
        }
        next.save(m_settings_file);
        m_settings = next;
        m_store.set_backup_retention(m_settings.backup_retention);
        return ok();
    });
}

std::string vault_bridge::settings_set_vault(const std::string& request) {
    return handle(request, 1, context::other, [&](json& args) {
        const json& o = args[0];
        if (!o.is_object()) bad_argument();
        vault_preferences p = vault_preferences::from(m_store.document());
        auto number = [&](const char* key, std::uint32_t& target) {
            if (const auto it = o.find(key); it != o.end()) {
                const auto v = unsigned_number(*it);
                if (v > 0xFFFFFFFFu) bad_argument();
                target = static_cast<std::uint32_t>(v);
            }
        };
        number("autoLockMinutes", p.auto_lock_minutes);
        number("clipboardClearSeconds", p.clipboard_clear_seconds);
        if (const auto it = o.find("lockOnMinimize"); it != o.end()) p.lock_on_minimize = boolean(*it);
        if (const auto it = o.find("lockOnSessionLock"); it != o.end()) p.lock_on_session_lock = boolean(*it);
        try {
            p.validate();
        } catch (const std::invalid_argument&) {
            return fail("bad_settings", msg::bad_settings);
        }
        mutate(m_store, [&](vault_document& doc) { p.apply_to(doc); });
        return ok();
    });
}

// --- account ----------------------------------------------------------------

std::string vault_bridge::change_password(const std::string& request) {
    return handle(request, 2, context::other, [&](json& args) {
        const auto& current = string_ref(args[0]);
        const auto& next = string_ref(args[1]);
        if (vault_store::password_length(view(next)) < vault_store::MIN_PASSWORD_CHARS) {
            return fail("weak_password", msg::weak_password);
        }
        if (!m_store.verify_password(view(current))) return fail("wrong_password", msg::wrong_password);
        m_store.change_password(view(next));
        return ok();
    });
}

std::string vault_bridge::regenerate_recovery_key(const std::string& request) {
    return handle(request, 1, context::other, [&](json& args) {
        if (!m_store.verify_password(view(string_ref(args[0])))) {
            return fail("wrong_password", msg::wrong_password);
        }
        const recovery_key key = m_store.regenerate_recovery_key();
        return ok({{"recoveryKey", to_secure(key.to_text())}});
    });
}

std::string vault_bridge::remove_recovery_key(const std::string& request) {
    return handle(request, 1, context::other, [&](json& args) {
        if (!m_store.verify_password(view(string_ref(args[0])))) {
            return fail("wrong_password", msg::wrong_password);
        }
        m_store.remove_recovery_key();
        return ok();
    });
}

// --- backups ----------------------------------------------------------------

std::string vault_bridge::backups_list(const std::string& request) {
    return handle(request, 0, context::other, [&](json&) {
        json list = json::array();
        for (const auto& b : m_store.backups()) {
            list.push_back({{"name", utf8_path(b.path.filename())},
                            {"savedAt", to_secure(b.saved_at)},
                            {"revision", b.revision},
                            {"size", static_cast<std::uint64_t>(b.size)}});
        }
        return ok({{"backups", std::move(list)}});
    });
}

std::string vault_bridge::backup_restore(const std::string& request) {
    return handle(request, 2, context::other, [&](json& args) {
        if (!m_store.verify_password(view(string_ref(args[0])))) {
            return fail("wrong_password", msg::wrong_password);
        }
        std::filesystem::path path;
        try {
            path = backup_by_name(m_store, plain_string(args[1]));
        } catch (const pbexception&) {
            return fail("backup_not_found", msg::backup_not_found);
        }
        m_store.restore_backup(path);
        return ok({{"entries", m_store.document().entries.size()}});
    });
}

std::string vault_bridge::unlock_from_backup(const std::string& request) {
    return handle(request, 2, context::unlock, [&](json& args) {
        const auto& password = string_ref(args[0]);
        std::filesystem::path path;
        try {
            path = backup_by_name(m_store, plain_string(args[1]));
        } catch (const pbexception&) {
            return fail("backup_not_found", msg::backup_not_found);
        }
        m_store.unlock_from_backup(view(password), path);
        return ok({{"entries", m_store.document().entries.size()}});
    });
}

// --- tools ------------------------------------------------------------------

std::string vault_bridge::generate(const std::string& request) {
    return handle(request, 1, context::other, [&](json& args) {
        const json& o = args[0];
        if (!o.is_object()) bad_argument();
        password_options options;
        if (const auto it = o.find("length"); it != o.end()) {
            if (!it->is_number_unsigned()) return fail("bad_options", msg::generator);
            options.length = it->get<std::size_t>();
        }
        auto flag = [&](const char* key, bool& target) {
            if (const auto it = o.find(key); it != o.end()) target = boolean(*it);
        };
        flag("lowercase", options.lowercase);
        flag("uppercase", options.uppercase);
        flag("digits", options.digits);
        flag("symbols", options.symbols);
        flag("avoidAmbiguous", options.avoid_ambiguous);
        try {
            return ok({{"password", generate_password(options)}});
        } catch (const std::invalid_argument&) {
            return fail("bad_options", msg::generator);
        }
    });
}

std::string vault_bridge::generate_passphrase(const std::string& request) {
    return handle(request, 1, context::other, [&](json& args) {
        const json& o = args[0];
        if (!o.is_object()) bad_argument();
        passphrase_options options;
        if (const auto it = o.find("words"); it != o.end()) {
            if (!it->is_number_unsigned()) return fail("bad_options", msg::passphrase);
            options.words = it->get<std::size_t>();
        }
        if (const auto it = o.find("separator"); it != o.end()) options.separator = plain_string(*it);
        if (const auto it = o.find("capitalize"); it != o.end()) options.capitalize = boolean(*it);
        if (const auto it = o.find("includeNumber"); it != o.end()) options.include_number = boolean(*it);
        try {
            const auto bits = passphrase_entropy_bits(options);
            return ok({{"password", pb::generate_passphrase(options)}, {"bits", bits}});
        } catch (const std::invalid_argument&) {
            return fail("bad_options", msg::passphrase);
        }
    });
}

std::string vault_bridge::app_info(const std::string& request) {
    return handle(request, 0, context::other, [&](json&) {
        return ok({{"version", PB_VERSION_STRING},
                   {"wordlistSize", passphrase_wordlist_size()}});
    });
}

} // namespace pb::app
