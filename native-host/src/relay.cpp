#include "relay.h"

#include "crypto/secure_allocator.h"

#include <sodium.h>

#include <array>
#include <string_view>
#include <vector>

#ifndef PB_VERSION_STRING
#define PB_VERSION_STRING "0.0.0-dev"
#endif

namespace pb::host {

namespace {

// Requests may carry the master password (unlock): parse into wiped memory.
using json = secure_json;

constexpr int PROTOCOL_VERSION = 1;

// Requests relayed to the app. Everything else is answered here or refused;
// "hello" in particular only ever comes from the host itself.
constexpr std::array<std::string_view, 13> FORWARDED = {
    "pair_begin", "pair_status", "auth_begin",  "auth_finish", "status",       "unlock", "lock",
    "matches",    "search",      "credentials", "generate",    "save_preview", "save",
};

std::string dump(const json& js) {
    const secure_string out = js.dump(-1, ' ', true, json::error_handler_t::replace);
    return std::string(out.data(), out.size());
}

json result(std::optional<std::uint64_t> id, bool ok, const char* code, const char* message) {
    json js = {{"ok", ok}, {"code", code}, {"message", message}};
    if (id) js["id"] = *id;
    return js;
}

void wipe(std::string& s) {
    if (!s.empty()) sodium_memzero(s.data(), s.size());
}

std::optional<std::uint64_t> id_of(const std::string& text) {
    try {
        const json js = json::parse(text);
        if (const auto it = js.find("id"); it != js.end() && it->is_number_unsigned()) return it->get<std::uint64_t>();
    } catch (...) {
    }
    return std::nullopt;
}

} // namespace

relay::relay(std::string origin, std::string endpoint, std::function<bool()> launch_app)
    : m_origin(std::move(origin)), m_endpoint(std::move(endpoint)), m_launch_app(std::move(launch_app)) {}

relay::~relay() { disconnect(); }

std::string relay::origin_from_args(int argc, char** argv) {
    if (argc > 1 && std::string_view(argv[1]).rfind("chrome-extension://", 0) == 0) return argv[1];
    if (argc > 2) return argv[2];
    return {};
}

int relay::run(browser_io io) {
    m_io = std::move(io);
    while (auto message = m_io.read()) {
        handle(*message);
        wipe(*message);
    }
    disconnect();
    return 0;
}

void relay::reply(const std::string& text) {
    std::lock_guard<std::mutex> lock(m_write_mutex);
    m_io.write(text);
}

void relay::reply_error(std::optional<std::uint64_t> id, const char* code, const char* message) {
    reply(dump(result(id, false, code, message)));
}

void relay::handle(std::string& message) {
    std::optional<std::uint64_t> id;
    std::string type;
    try {
        if (message.size() > MAX_BROWSER_MESSAGE) throw std::length_error("too large");
        const json req = json::parse(message.begin(), message.end());
        if (!req.is_object()) throw std::invalid_argument("not an object");
        if (const auto it = req.find("id"); it != req.end() && it->is_number_unsigned()) {
            id = it->get<std::uint64_t>();
        }
        const auto t = req.find("type");
        if (!id || t == req.end() || !t->is_string() || t->get_ref<const secure_string&>().size() > 64) {
            throw std::invalid_argument("missing id or type");
        }
        const auto& s = t->get_ref<const secure_string&>();
        type.assign(s.data(), s.size());
    } catch (...) {
        reply_error(id, "bad_request", "Invalid request.");
        return;
    }

    if (type == "ping") { // is the host installed? (no app needed)
        json js = result(id, true, "", "");
        js["host"] = PB_VERSION_STRING;
        js["protocol"] = PROTOCOL_VERSION;
        reply(dump(js));
        return;
    }
    if (type == "launch_app") {
        if (m_launch_app && m_launch_app()) reply(dump(result(id, true, "", "")));
        else reply_error(id, "launch_failed", "The PhylaxBox app could not be started.");
        return;
    }
    bool known = false;
    for (auto f : FORWARDED) known = known || f == type;
    if (!known) {
        reply_error(id, "unknown_type", "Unknown request type.");
        return;
    }

    std::shared_ptr<ipc::connection> conn;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_conn_alive) conn = m_conn;
    }
    if (!conn) {
        if (const auto error = connect()) {
            reply_error(id, error->c_str(), "The PhylaxBox app is not available.");
            return;
        }
        std::lock_guard<std::mutex> lock(m_mutex);
        conn = m_conn;
    }
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_pending.insert(*id);
    }
    if (!conn->write(message)) {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_pending.erase(*id);
        }
        disconnect(); // answers whatever else was waiting
        reply_error(id, "app_unavailable", "The PhylaxBox app is not available.");
    }
}

std::optional<std::string> relay::connect() {
    disconnect();
    auto c = ipc::connection::connect(m_endpoint);
    if (!c) return std::string("app_unavailable");
    const json hello = {{"id", 0}, {"type", "hello"}, {"protocol", PROTOCOL_VERSION}, {"origin", m_origin}};
    if (!c->write(dump(hello))) return std::string("app_unavailable");
    const auto answer = c->read();
    if (!answer) return std::string("app_unavailable");
    try {
        const json js = json::parse(*answer);
        if (!js.value("ok", false)) {
            const auto code = js.value("code", secure_string("app_unavailable"));
            return std::string(code.data(), code.size()); // e.g. origin_not_allowed
        }
    } catch (...) {
        return std::string("app_unavailable");
    }
    auto shared = std::make_shared<ipc::connection>(std::move(*c));
    std::lock_guard<std::mutex> lock(m_mutex);
    m_conn = shared;
    m_conn_alive = true;
    m_pending.clear();
    m_reader = std::thread([this, shared] { read_replies(shared); });
    return std::nullopt;
}

void relay::read_replies(std::shared_ptr<ipc::connection> conn) {
    while (auto answer = conn->read()) {
        if (const auto id = id_of(*answer)) {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_pending.erase(*id);
        }
        reply(*answer);
        wipe(*answer);
    }
    // The app went away (or we closed the channel): nothing waits in vain.
    std::set<std::uint64_t> orphans;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_conn == conn) m_conn_alive = false;
        orphans.swap(m_pending);
    }
    for (const auto id : orphans) reply_error(id, "app_unavailable", "The PhylaxBox app is not available.");
}

void relay::disconnect() {
    std::shared_ptr<ipc::connection> conn;
    std::thread reader;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        conn = std::move(m_conn);
        m_conn_alive = false;
        reader = std::move(m_reader);
    }
    if (conn) conn->close();
    if (reader.joinable()) reader.join();
}

} // namespace pb::host
