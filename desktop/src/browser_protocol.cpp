#include "browser_protocol.h"

#include "bridge_reply.h"
#include "crypto/crypto.h"
#include "models/vault_document.h"
#include "models/vault_preferences.h"
#include "web/site_match.h"

#include <sodium.h>

#include <algorithm>
#include <cctype>
#include <stdexcept>

#ifndef PB_VERSION_STRING
#define PB_VERSION_STRING "0.0.0-dev"
#endif

namespace pb::app {

namespace {

namespace msg {
const char* bad_request = "Invalid request.";
const char* hello_required = "The connection must start with hello.";
const char* unsupported_protocol = "This version of the extension is not supported by the app.";
const char* origin_not_allowed = "This extension is not allowed to connect.";
const char* busy = "Too many pairing requests are waiting.";
const char* pairing_unknown = "No such pairing request.";
const char* pairing_denied = "The connection was refused in the PhylaxBox app.";
const char* pairing_expired = "The pairing request expired.";
const char* too_many = "Too many browsers are paired. Remove one in the app settings.";
const char* not_paired = "This browser is not paired with the app.";
const char* auth_failed = "The browser could not be authenticated.";
const char* not_authenticated = "Authenticate first.";
const char* unknown_type = "Unknown request type.";
const char* locked = "The vault is locked.";
const char* unsupported_page = "Only http and https pages can be filled.";
const char* entry_not_found = "This item no longer exists.";
const char* site_mismatch = "This login belongs to another site.";
const char* internal = "Internal error.";
} // namespace msg

constexpr std::size_t MAX_URL = 4096;
constexpr std::size_t MAX_QUERY = 200;
constexpr std::size_t MAX_MATCHES = 100;
constexpr std::size_t MAX_SEARCH_RESULTS = 50;
constexpr std::size_t CHALLENGE_BYTES = 32;
const char AUTH_LABEL[] = "phylaxbox-browser-auth-v1";

// A failure reported to the extension as {"ok": false, "code": ...}.
struct protocol_error {
    const char* code;
    const char* message;
};

[[noreturn]] void bad_request() { throw protocol_error{"bad_request", msg::bad_request}; }

const secure_string& string_arg(const json& req, const char* key, std::size_t max_bytes) {
    const auto it = req.find(key);
    if (it == req.end() || !it->is_string()) bad_request();
    const auto& s = it->get_ref<const secure_string&>();
    if (s.size() > max_bytes) bad_request();
    return s;
}

std::string plain_arg(const json& req, const char* key, std::size_t max_bytes) {
    const auto& s = string_arg(req, key, max_bytes);
    return std::string(s.data(), s.size());
}

bool bool_arg(const json& req, const char* key) {
    const auto it = req.find(key);
    if (it == req.end() || it->is_null()) return false;
    if (!it->is_boolean()) bad_request();
    return it->get<bool>();
}

std::string random_hex(std::size_t bytes) {
    std::vector<unsigned char> raw(bytes);
    crypto::random_bytes(raw.data(), raw.size());
    std::string out(bytes * 2 + 1, '\0');
    sodium_bin2hex(out.data(), out.size(), raw.data(), raw.size());
    out.pop_back();
    return out;
}

// "Chrome", "Edge", "Firefox"...: printable, short, nothing to inject.
std::string sanitize_browser_name(std::string_view raw) {
    std::string out;
    for (char c : raw) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == ' ' || c == '.' || c == '-' || c == '(' ||
            c == ')') {
            out.push_back(c);
        }
        if (out.size() >= 40) break;
    }
    while (!out.empty() && out.back() == ' ') out.pop_back();
    return out.empty() ? "Browser" : out;
}

secure_string lowercase(std::string_view s) {
    secure_string out(s.data(), s.size());
    for (char& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

bool contains(const secure_string& haystack_lower, const secure_string& needle_lower) {
    return view(haystack_lower).find(view(needle_lower)) != std::string_view::npos;
}

// The best match of any of the entry's addresses with the page.
web::match_kind best_match(const vault_entry& e, const web::site& page) {
    auto best = web::match_kind::none;
    for (const auto& url : e.urls) {
        if (const auto saved = web::parse_site(view(url), true)) {
            best = std::max(best, web::match(*saved, page));
        }
    }
    return best;
}

const char* match_name(web::match_kind m) {
    switch (m) {
    case web::match_kind::exact: return "exact";
    case web::match_kind::domain: return "domain";
    default: return "none";
    }
}

// Host of the first saved address that is a web site ("" if none).
secure_string first_site(const vault_entry& e) {
    for (const auto& url : e.urls) {
        if (const auto saved = web::parse_site(view(url), true)) return to_secure(saved->host);
    }
    return {};
}

web::site page_arg(const json& req) {
    const auto page = web::parse_site(plain_arg(req, "url", MAX_URL));
    if (!page) throw protocol_error{"unsupported_page", msg::unsupported_page};
    return *page;
}

secure_string hmac(const secure_string& key, const secure_string& message) {
    secure_string out(crypto_auth_hmacsha256_BYTES, '\0');
    crypto_auth_hmacsha256(reinterpret_cast<unsigned char*>(out.data()),
                           reinterpret_cast<const unsigned char*>(message.data()), message.size(),
                           reinterpret_cast<const unsigned char*>(key.data()));
    return out;
}

json parse_reply(const std::string& text) { return json::parse(text); }

} // namespace

// --- pairing_broker -----------------------------------------------------------

std::optional<pairing_broker::request> pairing_broker::open(const std::string& browser, const std::string& origin) {
    request req;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto now = std::chrono::steady_clock::now();
        std::size_t waiting = 0;
        for (const auto& [id, e] : m_requests) {
            if (e.st == state::pending && e.expires > now) ++waiting;
        }
        if (waiting >= MAX_PENDING) return std::nullopt;
        req.id = random_hex(16);
        std::uint32_t n = 0;
        crypto::random_bytes(reinterpret_cast<std::uint8_t*>(&n), sizeof(n));
        const std::string digits = std::to_string(100000 + n % 900000);
        req.code = digits.substr(0, 3) + " " + digits.substr(3);
        req.browser = browser;
        req.origin = origin;
        m_requests[req.id] = entry{req, state::pending, now + LIFETIME};
    }
    if (on_open) on_open(req);
    return req;
}

pairing_broker::state pairing_broker::status(const std::string& id) {
    bool expired_now = false;
    state st;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto it = m_requests.find(id);
        if (it == m_requests.end()) return state::unknown;
        if (it->second.st == state::pending && it->second.expires <= std::chrono::steady_clock::now()) {
            it->second.st = state::expired;
            expired_now = true;
        }
        st = it->second.st;
    }
    if (expired_now && on_close) on_close(id);
    return st;
}

bool pairing_broker::answer(const std::string& id, bool approve) {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto it = m_requests.find(id);
        if (it == m_requests.end() || it->second.st != state::pending ||
            it->second.expires <= std::chrono::steady_clock::now()) {
            return false;
        }
        it->second.st = approve ? state::approved : state::denied;
    }
    if (on_close) on_close(id);
    return true;
}

void pairing_broker::forget(const std::string& id) {
    bool was_pending = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto it = m_requests.find(id);
        if (it == m_requests.end()) return;
        was_pending = it->second.st == state::pending;
        m_requests.erase(it);
    }
    if (was_pending && on_close) on_close(id);
}

std::vector<pairing_broker::request> pairing_broker::pending() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<request> out;
    const auto now = std::chrono::steady_clock::now();
    for (const auto& [id, e] : m_requests) {
        if (e.st == state::pending && e.expires > now) out.push_back(e.req);
    }
    return out;
}

// --- browser_session ----------------------------------------------------------

browser_session::browser_session(vault_store& store, vault_bridge& bridge, browser_pairings& pairings,
                                 pairing_broker& broker, browser_hooks hooks,
                                 std::vector<std::string> allowed_origins)
    : m_store(store), m_bridge(bridge), m_pairings(pairings), m_broker(broker), m_hooks(std::move(hooks)),
      m_allowed_origins(std::move(allowed_origins)) {
    if (!m_hooks.now) m_hooks.now = [] { return utc_now(); };
}

browser_session::~browser_session() {
    if (m_pairing_id) m_broker.forget(*m_pairing_id);
}

secure_string browser_session::auth_message(bool client, const secure_string& server_challenge,
                                            const secure_string& client_challenge) {
    secure_string m(AUTH_LABEL, sizeof(AUTH_LABEL)); // includes the terminating NUL
    m += client ? "client" : "server";
    m.push_back('\0');
    m += server_challenge;
    m += client_challenge;
    return m;
}

std::string browser_session::handle(std::string& request) {
    json reply;
    std::optional<std::uint64_t> id;
    try {
        if (request.size() > MAX_BROWSER_REQUEST) bad_request();
        const json req = json::parse(request.begin(), request.end());
        sodium_memzero(request.data(), request.size());
        if (!req.is_object()) bad_request();
        if (const auto it = req.find("id"); it != req.end() && it->is_number_unsigned()) {
            id = it->get<std::uint64_t>();
        }
        reply = dispatch(plain_arg(req, "type", 64), req);
    } catch (const protocol_error& e) {
        reply = fail_json(e.code, e.message);
    } catch (const json::exception&) {
        reply = fail_json("bad_request", msg::bad_request);
    } catch (...) {
        reply = fail_json("internal_error", msg::internal);
    }
    sodium_memzero(request.data(), request.size());
    if (id) reply["id"] = *id;
    return to_reply(reply);
}

json browser_session::dispatch(const std::string& type, const json& req) {
    if (m_origin.empty()) {
        if (type != "hello") throw protocol_error{"hello_required", msg::hello_required};
        return hello(req);
    }
    if (type == "pair_begin") return pair_begin(req);
    if (type == "pair_status") return pair_status(req);
    if (type == "auth_begin") return auth_begin(req);
    if (type == "auth_finish") return auth_finish(req);

    static const char* const authenticated_types[] = {"status", "unlock",      "lock",    "matches",
                                                       "search", "credentials", "generate"};
    if (std::find_if(std::begin(authenticated_types), std::end(authenticated_types),
                     [&](const char* t) { return type == t; }) == std::end(authenticated_types)) {
        throw protocol_error{"unknown_type", msg::unknown_type};
    }
    if (m_authenticated.empty()) throw protocol_error{"not_authenticated", msg::not_authenticated};
    if (!m_pairings.find(m_authenticated)) { // revoked in the app meanwhile
        m_authenticated.clear();
        throw protocol_error{"not_paired", msg::not_paired};
    }
    if (m_hooks.on_activity) m_hooks.on_activity();

    if (type == "status") return vault_status();
    if (type == "unlock") return unlock(req);
    if (type == "lock") return lock();
    if (type == "matches") return matches(req);
    if (type == "search") return search(req);
    if (type == "credentials") return credentials(req);
    return generate(req);
}

json browser_session::hello(const json& req) {
    const auto it = req.find("protocol");
    if (it == req.end() || !it->is_number_unsigned() || it->get<std::uint64_t>() != BROWSER_PROTOCOL_VERSION) {
        json reply = fail_json("unsupported_protocol", msg::unsupported_protocol);
        reply["protocol"] = BROWSER_PROTOCOL_VERSION;
        return reply;
    }
    const std::string origin = plain_arg(req, "origin", 256);
    if (origin.empty() ||
        std::find(m_allowed_origins.begin(), m_allowed_origins.end(), origin) == m_allowed_origins.end()) {
        throw protocol_error{"origin_not_allowed", msg::origin_not_allowed};
    }
    m_origin = origin;
    return ok_json({{"protocol", BROWSER_PROTOCOL_VERSION}, {"app", PB_VERSION_STRING}});
}

json browser_session::pair_begin(const json& req) {
    const std::string name = sanitize_browser_name(plain_arg(req, "browser", 256));
    if (m_pairing_id) {
        m_broker.forget(*m_pairing_id);
        m_pairing_id.reset();
    }
    const auto opened = m_broker.open(name, m_origin);
    if (!opened) throw protocol_error{"busy", msg::busy};
    m_pairing_id = opened->id;
    m_pairing_browser = name;
    return ok_json({{"pairingId", to_secure(opened->id)}, {"verificationCode", to_secure(opened->code)}});
}

json browser_session::pair_status(const json& req) {
    const std::string id = plain_arg(req, "pairingId", 64);
    if (!m_pairing_id || *m_pairing_id != id) throw protocol_error{"pairing_unknown", msg::pairing_unknown};
    const auto st = m_broker.status(id);
    if (st == pairing_broker::state::pending) return ok_json({{"state", "pending"}});

    m_broker.forget(id);
    m_pairing_id.reset();
    if (st == pairing_broker::state::denied) throw protocol_error{"pairing_denied", msg::pairing_denied};
    if (st != pairing_broker::state::approved) throw protocol_error{"pairing_expired", msg::pairing_expired};
    browser_client client;
    try {
        client = m_pairings.add(m_pairing_browser, m_origin, m_hooks.now());
    } catch (const std::length_error&) {
        throw protocol_error{"too_many_browsers", msg::too_many};
    }
    return ok_json({{"state", "approved"}, {"clientId", to_secure(client.id)}, {"key", base64_encode(client.key)}});
}

json browser_session::auth_begin(const json& req) {
    const std::string client_id = plain_arg(req, "clientId", 64);
    const auto client = m_pairings.find(client_id);
    if (!client || client->origin != m_origin) throw protocol_error{"not_paired", msg::not_paired};
    m_server_challenge.assign(CHALLENGE_BYTES, '\0');
    crypto::random_bytes(reinterpret_cast<std::uint8_t*>(m_server_challenge.data()), m_server_challenge.size());
    m_challenge_client = client_id;
    m_authenticated.clear();
    return ok_json({{"challenge", base64_encode(m_server_challenge)}});
}

json browser_session::auth_finish(const json& req) {
    const std::string client_id = plain_arg(req, "clientId", 64);
    const auto client_challenge = base64_decode(string_arg(req, "clientChallenge", 128), CHALLENGE_BYTES);
    const auto proof = base64_decode(string_arg(req, "proof", 128), crypto_auth_hmacsha256_BYTES);
    // One attempt per challenge.
    const secure_string server_challenge = std::move(m_server_challenge);
    m_server_challenge.clear();
    const bool challenged = !server_challenge.empty() && client_id == m_challenge_client;
    m_challenge_client.clear();

    const auto client = challenged ? m_pairings.find(client_id) : std::nullopt;
    bool valid = false;
    if (client && client->origin == m_origin && client_challenge && proof) {
        const secure_string signed_text = auth_message(true, server_challenge, *client_challenge);
        valid = crypto_auth_hmacsha256_verify(reinterpret_cast<const unsigned char*>(proof->data()),
                                              reinterpret_cast<const unsigned char*>(signed_text.data()),
                                              signed_text.size(),
                                              reinterpret_cast<const unsigned char*>(client->key.data())) == 0;
    }
    if (!valid) {
        ++m_auth_failures;
        throw protocol_error{"auth_failed", msg::auth_failed};
    }
    m_authenticated = client_id;
    m_pairings.touch(client_id, m_hooks.now());
    const secure_string server_proof = hmac(client->key, auth_message(false, server_challenge, *client_challenge));
    return ok_json({{"serverProof", base64_encode(server_proof)}});
}

json browser_session::on_worker(const std::function<json()>& job) {
    json result;
    auto run = [&] {
        try {
            result = job();
        } catch (const protocol_error& e) {
            result = fail_json(e.code, e.message);
        } catch (...) {
            result = fail_json("internal_error", msg::internal);
        }
    };
    if (m_hooks.run_on_worker) m_hooks.run_on_worker(run);
    else run();
    return result;
}

json browser_session::vault_status() {
    return on_worker([&] {
        return ok_json({{"exists", m_store.exists()}, {"unlocked", m_store.is_unlocked()}});
    });
}

json browser_session::unlock(const json& req) {
    std::string args = to_reply(json::array({string_arg(req, "password", 4096)}));
    json reply = on_worker([&] { return parse_reply(m_bridge.unlock(args)); });
    sodium_memzero(args.data(), args.size());
    if (reply.value("ok", false) && m_hooks.on_vault_unlocked) m_hooks.on_vault_unlocked();
    return reply;
}

json browser_session::lock() {
    json reply = on_worker([&] { return parse_reply(m_bridge.lock("[]")); });
    if (reply.value("ok", false) && m_hooks.on_vault_locked) m_hooks.on_vault_locked();
    return reply;
}

json browser_session::matches(const json& req) {
    const web::site page = page_arg(req);
    return on_worker([&] {
        if (!m_store.is_unlocked()) return fail_json("locked", msg::locked);
        struct found {
            const vault_entry* entry;
            web::match_kind kind;
            secure_string title_lower;
        };
        std::vector<found> list;
        for (const auto& e : m_store.document().entries) {
            const auto kind = best_match(e, page);
            if (kind != web::match_kind::none) list.push_back({&e, kind, lowercase(view(e.title))});
        }
        std::sort(list.begin(), list.end(), [](const found& a, const found& b) {
            if (a.kind != b.kind) return a.kind > b.kind;
            if (a.entry->favorite != b.entry->favorite) return a.entry->favorite;
            return a.title_lower < b.title_lower;
        });
        if (list.size() > MAX_MATCHES) list.resize(MAX_MATCHES);
        json entries = json::array();
        for (const auto& f : list) {
            entries.push_back({{"id", to_secure(f.entry->id)},
                               {"title", f.entry->title},
                               {"username", f.entry->username},
                               {"favorite", f.entry->favorite},
                               {"match", match_name(f.kind)}});
        }
        const auto domain = web::registrable_domain(page.host);
        return ok_json({{"site", {{"host", to_secure(page.host)}, {"domain", to_secure(domain ? *domain : page.host)}}},
                        {"entries", std::move(entries)}});
    });
}

json browser_session::search(const json& req) {
    const secure_string query = lowercase(view(string_arg(req, "query", MAX_QUERY)));
    std::optional<web::site> page;
    if (const auto it = req.find("url"); it != req.end() && !it->is_null()) {
        page = web::parse_site(plain_arg(req, "url", MAX_URL));
    }
    return on_worker([&] {
        if (!m_store.is_unlocked()) return fail_json("locked", msg::locked);
        struct found {
            const vault_entry* entry;
            secure_string title_lower;
        };
        std::vector<found> list;
        for (const auto& e : m_store.document().entries) {
            secure_string title = lowercase(view(e.title));
            bool hit = query.empty() || contains(title, query) || contains(lowercase(view(e.username)), query);
            for (const auto& u : e.urls) hit = hit || contains(lowercase(view(u)), query);
            for (const auto& t : e.tags) hit = hit || contains(lowercase(view(t)), query);
            if (hit) list.push_back({&e, std::move(title)});
        }
        std::sort(list.begin(), list.end(),
                  [](const found& a, const found& b) { return a.title_lower < b.title_lower; });
        const bool truncated = list.size() > MAX_SEARCH_RESULTS;
        if (truncated) list.resize(MAX_SEARCH_RESULTS);
        json entries = json::array();
        for (const auto& f : list) {
            entries.push_back({{"id", to_secure(f.entry->id)},
                               {"title", f.entry->title},
                               {"username", f.entry->username},
                               {"site", first_site(*f.entry)},
                               {"match", match_name(page ? best_match(*f.entry, *page) : web::match_kind::none)}});
        }
        return ok_json({{"entries", std::move(entries)}, {"truncated", truncated}});
    });
}

json browser_session::credentials(const json& req) {
    const std::string id = plain_arg(req, "entryId", 64);
    const web::site page = page_arg(req);
    const bool allow_mismatch = bool_arg(req, "allowMismatch");
    return on_worker([&] {
        if (!m_store.is_unlocked()) return fail_json("locked", msg::locked);
        const vault_entry* e = m_store.document().find(id);
        if (!e) return fail_json("entry_not_found", msg::entry_not_found);
        const auto kind = best_match(*e, page);
        if (kind == web::match_kind::none && !allow_mismatch) {
            json reply = fail_json("site_mismatch", msg::site_mismatch);
            reply["site"] = first_site(*e);
            return reply;
        }
        return ok_json({{"username", e->username}, {"password", e->password}, {"match", match_name(kind)}});
    });
}

json browser_session::generate(const json& req) {
    const auto it = req.find("options");
    if (it == req.end() || !it->is_object()) bad_request();
    json options = *it;
    const std::string kind = options.contains("kind") ? plain_arg(options, "kind", 16) : "password";
    if (kind != "password" && kind != "passphrase") bad_request();
    options.erase("kind");
    const bool copy = bool_arg(req, "copy");
    const std::string args = to_reply(json::array({options}));
    return on_worker([&] {
        json reply = parse_reply(kind == "password" ? m_bridge.generate(args) : m_bridge.generate_passphrase(args));
        if (!copy || !reply.value("ok", false)) return reply;
        std::chrono::seconds clear_after(vault_preferences{}.clipboard_clear_seconds);
        if (m_store.is_unlocked()) {
            clear_after = std::chrono::seconds(vault_preferences::from(m_store.document()).clipboard_clear_seconds);
        }
        secure_string text = reply["password"].get<secure_string>();
        const bool copied = m_hooks.copy_to_clipboard && m_hooks.copy_to_clipboard(std::move(text), clear_after);
        reply["copied"] = copied;
        if (copied) reply["clearsIn"] = clear_after.count();
        return reply;
    });
}

} // namespace pb::app
