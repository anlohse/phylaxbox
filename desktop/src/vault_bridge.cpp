#include "vault_bridge.h"

#include "models/pbexceptions.h"

#include <nlohmann/json.hpp>
#include <sodium.h>

#include <exception>
#include <functional>

namespace pb::app {

namespace {

using json = nlohmann::json;

// Messages shown by the (Portuguese) UI. Kept here so every error the core
// can raise has a deliberate, user-facing explanation.
namespace msg {
const char* bad_request = "Requisi\xC3\xA7\xC3\xA3o inv\xC3\xA1lida.";
const char* internal = "Erro interno. Nenhuma altera\xC3\xA7\xC3\xA3o foi gravada.";
const char* wrong_password = "Senha mestra incorreta.";
const char* wrong_recovery = "Chave de recupera\xC3\xA7\xC3\xA3o incorreta para este cofre.";
const char* invalid_recovery =
    "Chave de recupera\xC3\xA7\xC3\xA3o inv\xC3\xA1lida. Confira se foi digitada corretamente.";
const char* no_recovery = "Este cofre n\xC3\xA3o tem chave de recupera\xC3\xA7\xC3\xA3o.";
const char* weak_password = "A senha mestra precisa ter pelo menos 8 caracteres.";
const char* exists = "J\xC3\xA1 existe um cofre neste computador.";
const char* not_found = "Nenhum cofre foi encontrado neste computador.";
const char* io = "N\xC3\xA3o foi poss\xC3\xADvel ler ou gravar o arquivo do cofre.";
const char* integrity =
    "O arquivo do cofre est\xC3\xA1 corrompido ou foi alterado. Use o backup (.bak) se necess\xC3\xA1rio.";
const char* newer = "Este cofre foi criado por uma vers\xC3\xA3o mais nova do PhylaxBox.";
const char* invalid_file = "O arquivo n\xC3\xA3o \xC3\xA9 um cofre PhylaxBox v\xC3\xA1lido.";
const char* save_failed =
    "A grava\xC3\xA7\xC3\xA3o n\xC3\xA3o p\xC3\xB4" "de ser verificada. O arquivo anterior foi mantido.";
} // namespace msg

std::string dump(const json& js) {
    // ASCII-only: the reply is spliced into JavaScript by the webview.
    return js.dump(-1, ' ', true, json::error_handler_t::replace);
}

std::string fail(const char* code, const char* message) {
    return dump({{"ok", false}, {"code", code}, {"message", message}});
}

json ok(json extra = json::object()) {
    extra["ok"] = true;
    extra["code"] = "";
    extra["message"] = "";
    return extra;
}

void wipe(std::string& s) {
    if (!s.empty()) sodium_memzero(s.data(), s.size());
    s.clear();
}

// Parsed request whose string arguments are wiped on destruction.
struct args_t {
    json array;
    ~args_t() {
        for (auto& v : array) {
            if (v.is_string()) wipe(v.get_ref<std::string&>());
        }
    }
};

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
        default: return fail("internal_error", msg::internal);
        }
    } catch (const json::exception&) {
        return fail("bad_request", msg::bad_request);
    } catch (...) {
        return fail("internal_error", msg::internal);
    }
}

// Runs `body` with the parsed arguments; maps every failure to a reply.
std::string handle(const std::string& request, std::size_t expected_args, context ctx,
                   const std::function<std::string(json& args)>& body) {
    try {
        args_t args;
        args.array = json::parse(request);
        if (!args.array.is_array() || args.array.size() != expected_args) {
            return fail("bad_request", msg::bad_request);
        }
        return body(args.array);
    } catch (...) {
        return from_exception(ctx);
    }
}

// Copies a string argument; the caller wipes the copy.
std::string string_arg(json& args, std::size_t i) {
    if (!args[i].is_string()) throw json::type_error::create(302, "expected a string", nullptr);
    return args[i].get<std::string>();
}

struct scoped_secret {
    std::string value;
    ~scoped_secret() { wipe(value); }
};

} // namespace

std::string vault_bridge::status(const std::string& request) {
    return handle(request, 0, context::other, [&](json&) {
        json reply = ok({{"exists", m_store.exists()}, {"unlocked", m_store.is_unlocked()}});
        if (m_store.is_unlocked()) {
            reply["entries"] = m_store.document().entries.size();
            reply["hasRecoveryKey"] = m_store.container().has_recovery_key();
        }
        return dump(reply);
    });
}

std::string vault_bridge::create(const std::string& request) {
    return handle(request, 2, context::other, [&](json& args) {
        scoped_secret password{string_arg(args, 0)};
        if (!args[1].is_boolean()) return fail("bad_request", msg::bad_request);
        const auto key = m_store.create(password.value, args[1].get<bool>());
        json reply = ok({{"recoveryKey", nullptr}});
        if (key) reply["recoveryKey"] = key->to_text();
        return dump(reply);
    });
}

std::string vault_bridge::unlock(const std::string& request) {
    return handle(request, 1, context::unlock, [&](json& args) {
        scoped_secret password{string_arg(args, 0)};
        if (password.value.empty()) return fail("empty_password", msg::wrong_password);
        m_store.unlock(password.value);
        return dump(ok({{"entries", m_store.document().entries.size()}}));
    });
}

std::string vault_bridge::recover(const std::string& request) {
    return handle(request, 2, context::recover, [&](json& args) {
        scoped_secret key_text{string_arg(args, 0)};
        scoped_secret new_password{string_arg(args, 1)};
        // Validate the new password before the (slower) unlock.
        if (vault_store::password_length(new_password.value) < vault_store::MIN_PASSWORD_CHARS) {
            return fail("weak_password", msg::weak_password);
        }
        const recovery_key key = recovery_key::parse(key_text.value);
        m_store.unlock_with_recovery_key(key);
        m_store.change_password(new_password.value);
        return dump(ok({{"entries", m_store.document().entries.size()}}));
    });
}

std::string vault_bridge::lock(const std::string& request) {
    return handle(request, 0, context::other, [&](json&) {
        m_store.lock();
        return dump(ok());
    });
}

} // namespace pb::app
