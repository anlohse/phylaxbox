#include "login_bridge.h"

#include <nlohmann/json.hpp>
#include <sodium.h>

#include <exception>

namespace pb::app {

namespace {

std::string reply(const login_result& r) {
    nlohmann::json js = {{"ok", r.ok}, {"code", r.code}, {"message", r.message}};
    // ASCII-only output: the result is spliced into JavaScript by the webview.
    return js.dump(-1, ' ', true, nlohmann::json::error_handler_t::replace);
}

login_result failure(const char* code, const char* message) {
    return login_result{false, code, message};
}

void wipe(std::string& s) {
    if (!s.empty()) sodium_memzero(s.data(), s.size());
    s.clear();
}

} // namespace

std::string handle_login_request(const std::string& request, const unlock_fn& unlock) {
    std::string password;
    login_result result;
    try {
        nlohmann::json args = nlohmann::json::parse(request);
        if (!args.is_array() || args.size() != 1 || !args[0].is_string()) {
            return reply(failure("bad_request", "Requisição inválida."));
        }
        password = args[0].get<std::string>();
        // Overwrite the parsed copy as well.
        auto& stored = args[0].get_ref<std::string&>();
        wipe(stored);

        if (password.empty()) {
            result = failure("empty_password", "Digite a senha mestra.");
        } else {
            result = unlock(password);
        }
    } catch (const nlohmann::json::exception&) {
        result = failure("bad_request", "Requisição inválida.");
    } catch (const std::exception&) {
        result = failure("internal_error", "Erro interno ao desbloquear o cofre.");
    }
    wipe(password);
    return reply(result);
}

} // namespace pb::app
