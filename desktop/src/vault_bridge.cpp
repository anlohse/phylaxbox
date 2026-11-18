#include "vault_bridge.h"

#include "crypto/password_generator.h"
#include "models/entry_ops.h"
#include "models/pbexceptions.h"

#include <sodium.h>

#include <exception>
#include <functional>
#include <stdexcept>

namespace pb::app {

namespace {

// Requests and replies use secure_json: whatever they contain (passwords,
// notes) lives in memory that is wiped when freed.
using json = secure_json;

// Messages shown by the (Portuguese) UI. Every error the core can raise has
// a deliberate, user-facing explanation here. (Source files are UTF-8.)
namespace msg {
const char* bad_request = "Requisição inválida.";
const char* internal = "Erro interno. Nenhuma alteração foi gravada.";
const char* wrong_password = "Senha mestra incorreta.";
const char* wrong_recovery = "Chave de recuperação incorreta para este cofre.";
const char* invalid_recovery = "Chave de recuperação inválida. Confira se foi digitada corretamente.";
const char* no_recovery = "Este cofre não tem chave de recuperação.";
const char* weak_password = "A senha mestra precisa ter pelo menos 8 caracteres.";
const char* exists = "Já existe um cofre neste computador.";
const char* not_found = "Nenhum cofre foi encontrado neste computador.";
const char* io = "Não foi possível ler ou gravar o arquivo do cofre.";
const char* integrity = "O arquivo do cofre está corrompido ou foi alterado. "
                        "As versões anteriores ficam na pasta \"backups\", ao lado do cofre.";
const char* newer = "Este cofre foi criado por uma versão mais nova do PhylaxBox.";
const char* invalid_file = "O arquivo não é um cofre PhylaxBox válido.";
const char* save_failed = "A gravação não pôde ser verificada. O arquivo anterior foi mantido.";
const char* locked = "O cofre está bloqueado.";
const char* entry_not_found = "Este item não existe mais.";
const char* title_required = "Informe um título.";
const char* invalid_entry = "Algum campo está longo demais ou contém caracteres inválidos.";
const char* clipboard = "Não foi possível copiar para a área de transferência.";
const char* generator = "Escolha um tamanho entre 8 e 128 e pelo menos um tipo de caractere.";
} // namespace msg

std::string to_reply(const json& js) {
    // ASCII-only: the reply is spliced into JavaScript by the webview.
    const secure_string out = js.dump(-1, ' ', true, json::error_handler_t::replace);
    return std::string(out.data(), out.size());
}

std::string fail(const char* code, const char* message) {
    return to_reply({{"ok", false}, {"code", code}, {"message", message}});
}

std::string ok(json extra = json::object()) {
    extra["ok"] = true;
    extra["code"] = "";
    extra["message"] = "";
    return to_reply(extra);
}

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
                return fail("invalid_entry", msg::title_required);
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

} // namespace

// --- session ---------------------------------------------------------------

std::string vault_bridge::status(const std::string& request) {
    return handle(request, 0, context::other, [&](json&) {
        json reply = {{"exists", m_store.exists()}, {"unlocked", m_store.is_unlocked()}};
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

// --- entries ---------------------------------------------------------------

namespace {

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

} // namespace

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
        if (!m_hooks.copy_to_clipboard || !m_hooks.copy_to_clipboard(std::move(text))) {
            return fail("clipboard_error", msg::clipboard);
        }
        return ok({{"clearsIn", CLIPBOARD_CLEAR_AFTER.count()}});
    });
}

// --- tools -----------------------------------------------------------------

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

} // namespace pb::app
