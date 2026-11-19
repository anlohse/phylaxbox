#include "browser_service.h"

#include "bridge_reply.h"

#include <sodium.h>

namespace pb::app {

namespace {

const char* bad_request = "Invalid request.";

// Parses a UI request that must be a JSON array of `n` strings or booleans.
json ui_args(const std::string& request, std::size_t n) {
    json args = json::parse(request);
    if (!args.is_array() || args.size() != n) throw std::invalid_argument("bad request");
    return args;
}

std::string str(const json& v) {
    if (!v.is_string()) throw std::invalid_argument("bad request");
    const auto& s = v.get_ref<const secure_string&>();
    return std::string(s.data(), s.size());
}

} // namespace

browser_service::browser_service(vault_store& store, vault_bridge& bridge, browser_pairings& pairings,
                                 browser_hooks hooks, std::vector<std::string> allowed_origins, ui_hooks ui)
    : m_store(store), m_bridge(bridge), m_pairings(pairings), m_hooks(std::move(hooks)),
      m_allowed_origins(std::move(allowed_origins)) {
    m_broker.on_open = std::move(ui.on_pairing_request);
    m_broker.on_close = std::move(ui.on_pairing_closed);
}

browser_service::~browser_service() { stop(); }

bool browser_service::start(const std::string& endpoint) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_listener || m_stopping) return false;
    m_listener = ipc::listener::create(endpoint);
    if (!m_listener) return false;
    m_accept_thread = std::thread([this] { accept_loop(); });
    return true;
}

void browser_service::stop() {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_stopping) return;
        m_stopping = true;
        if (m_listener) m_listener->close();
        for (auto& w : m_workers) w.conn->close();
    }
    if (m_accept_thread.joinable()) m_accept_thread.join();
    // No new workers can appear now.
    for (auto& w : m_workers) {
        if (w.thread.joinable()) w.thread.join();
    }
    m_workers.clear();
    m_listener.reset();
}

void browser_service::accept_loop() {
    for (;;) {
        auto conn = m_listener->accept();
        if (!conn) {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_stopping) return;
            continue; // a client that failed the checks
        }
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_stopping) return;
        reap_finished();
        if (m_workers.size() >= MAX_CONNECTIONS) continue; // dropped: closes the connection
        auto& w = m_workers.emplace_back();
        w.conn = std::make_shared<ipc::connection>(std::move(*conn));
        w.thread = std::thread([this, &w] { serve(w); });
    }
}

void browser_service::reap_finished() {
    for (auto it = m_workers.begin(); it != m_workers.end();) {
        if (it->done) {
            if (it->thread.joinable()) it->thread.join();
            it = m_workers.erase(it);
        } else {
            ++it;
        }
    }
}

void browser_service::serve(worker_thread& w) {
    {
        browser_session session(m_store, m_bridge, m_pairings, m_broker, m_hooks, m_allowed_origins);
        while (auto request = w.conn->read(MAX_BROWSER_REQUEST)) {
            std::string reply = session.handle(*request);
            const bool sent = w.conn->write(reply);
            sodium_memzero(reply.data(), reply.size());
            if (!sent || session.should_close()) break;
        }
    }
    w.conn->close();
    w.done = true;
}

std::string browser_service::pair_answer(const std::string& request) {
    try {
        const json args = ui_args(request, 2);
        if (!args[1].is_boolean()) throw std::invalid_argument("bad request");
        if (!m_broker.answer(str(args[0]), args[1].get<bool>())) {
            return fail("pairing_expired", "The pairing request expired.");
        }
        return ok();
    } catch (...) {
        return fail("bad_request", bad_request);
    }
}

std::string browser_service::clients(const std::string& request) {
    try {
        ui_args(request, 0);
        json list = json::array();
        for (const auto& c : m_pairings.list()) {
            list.push_back({{"id", to_secure(c.id)},
                            {"name", to_secure(c.name)},
                            {"origin", to_secure(c.origin)},
                            {"createdAt", to_secure(c.created_at)},
                            {"lastUsedAt", to_secure(c.last_used_at)}});
        }
        json pending = json::array();
        for (const auto& p : m_broker.pending()) {
            pending.push_back({{"id", to_secure(p.id)}, {"code", to_secure(p.code)}, {"browser", to_secure(p.browser)}});
        }
        return ok({{"clients", std::move(list)}, {"pending", std::move(pending)}});
    } catch (...) {
        return fail("bad_request", bad_request);
    }
}

std::string browser_service::revoke(const std::string& request) {
    try {
        const json args = ui_args(request, 1);
        if (!m_pairings.remove(str(args[0]))) return fail("not_paired", "This browser is not paired.");
        return ok();
    } catch (const std::invalid_argument&) {
        return fail("bad_request", bad_request);
    } catch (const json::exception&) {
        return fail("bad_request", bad_request);
    } catch (...) {
        return fail("io_error", "The list of browsers could not be saved.");
    }
}

} // namespace pb::app
