#ifndef PB_LOGIN_BRIDGE_H_
#define PB_LOGIN_BRIDGE_H_

#include <functional>
#include <string>
#include <string_view>

namespace pb::app {

struct login_result {
    bool ok = false;
    std::string code;    // machine-readable, e.g. "wrong_password"
    std::string message; // shown to the user (Portuguese UI)
};

using unlock_fn = std::function<login_result(std::string_view password)>;

// Handles the UI's `window.login(password)` call (webview bind).
// `request` is the JSON array of JavaScript arguments; the return value is the
// JSON the JavaScript promise resolves with: {"ok":bool,"code":...,"message":...}.
// Never throws, never echoes the password, and wipes its copy of it.
std::string handle_login_request(const std::string& request, const unlock_fn& unlock);

} // namespace pb::app

#endif // PB_LOGIN_BRIDGE_H_
