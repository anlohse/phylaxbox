#ifndef PB_BROWSER_SERVICE_H_
#define PB_BROWSER_SERVICE_H_

#include "browser_pairings.h"
#include "browser_protocol.h"
#include "ipc/local_channel.h"

#include <atomic>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace pb::app {

// Serves native messaging hosts on the local IPC endpoint: one thread per
// connection, each with its own browser_session. Also answers the desktop
// UI's calls about paired browsers (same JSON style as vault_bridge).
class browser_service {
public:
    static constexpr std::size_t MAX_CONNECTIONS = 8;

    struct ui_hooks {
        // A browser asks to be paired: show the request and its code.
        std::function<void(const pairing_broker::request&)> on_pairing_request;
        // The request was answered, expired or abandoned: hide it.
        std::function<void(const std::string& pairing_id)> on_pairing_closed;
    };

    browser_service(vault_store& store, vault_bridge& bridge, browser_pairings& pairings, browser_hooks hooks,
                    std::vector<std::string> allowed_origins, ui_hooks ui = {});
    ~browser_service();

    browser_service(const browser_service&) = delete;
    browser_service& operator=(const browser_service&) = delete;

    // Starts listening. False when the endpoint is taken (e.g. another
    // instance of the app is running): the browser extension then talks to
    // that one.
    bool start(const std::string& endpoint);
    // Closes the endpoint and every connection, and joins the threads.
    // Requests already queued on the vault worker still complete first.
    void stop();

    pairing_broker& broker() { return m_broker; }

    // --- desktop UI ---------------------------------------------------------
    // [pairingId, approve] -> {}
    std::string pair_answer(const std::string& request);
    // [] -> {clients: [{id, name, origin, createdAt, lastUsedAt}], pending: [{id, code, browser}]}
    std::string clients(const std::string& request);
    // [clientId] -> {}
    std::string revoke(const std::string& request);

private:
    struct worker_thread {
        std::shared_ptr<ipc::connection> conn;
        std::thread thread;
        std::atomic<bool> done{false};
    };

    void accept_loop();
    void serve(worker_thread& w);
    void reap_finished(); // with m_mutex held

    vault_store& m_store;
    vault_bridge& m_bridge;
    browser_pairings& m_pairings;
    browser_hooks m_hooks;
    std::vector<std::string> m_allowed_origins;
    pairing_broker m_broker;

    std::unique_ptr<ipc::listener> m_listener;
    std::thread m_accept_thread;
    std::mutex m_mutex;
    std::list<worker_thread> m_workers;
    bool m_stopping = false;
};

} // namespace pb::app

#endif // PB_BROWSER_SERVICE_H_
