#ifndef PB_BRIDGE_REPLY_H_
#define PB_BRIDGE_REPLY_H_

#include "crypto/secure_allocator.h"

#include <string>

// Replies of the UI bridge and of the browser protocol:
// {"ok": bool, "code": str, "message": str, ...}. `code` is the contract
// (the UI translates it); `message` is an English fallback.
namespace pb::app {

// Requests and replies may hold passwords: keep them in wiped memory.
using json = secure_json;

// ASCII-only JSON text (the UI reply is spliced into JavaScript).
inline std::string to_reply(const json& js) {
    const secure_string out = js.dump(-1, ' ', true, json::error_handler_t::replace);
    return std::string(out.data(), out.size());
}

inline json fail_json(const char* code, const char* message) {
    return {{"ok", false}, {"code", code}, {"message", message}};
}

inline std::string fail(const char* code, const char* message) { return to_reply(fail_json(code, message)); }

inline json ok_json(json extra = json::object()) {
    extra["ok"] = true;
    extra["code"] = "";
    extra["message"] = "";
    return extra;
}

inline std::string ok(json extra = json::object()) { return to_reply(ok_json(std::move(extra))); }

} // namespace pb::app

#endif // PB_BRIDGE_REPLY_H_
