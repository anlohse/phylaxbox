#ifndef PB_BROWSER_PROTOCOL_H_
#define PB_BROWSER_PROTOCOL_H_

#include "browser_pairings.h"
#include "crypto/secure_allocator.h"
#include "storage/vault_store.h"
#include "vault_bridge.h"

#include <chrono>
#include <cstddef>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

// The desktop side of the browser protocol (docs/browser-integration/protocol.md):
// pairing, authentication of the extension, and the requests it may make.
namespace pb::app {

constexpr int BROWSER_PROTOCOL_VERSION = 1;
// Largest request accepted from the extension (passwords, URLs, queries).
constexpr std::size_t MAX_BROWSER_REQUEST = 64 * 1024;

// Pairing requests waiting for the user's answer in the desktop window.
// Thread-safe: sessions open and poll requests, the UI answers them.
class pairing_broker {
public:
    static constexpr std::size_t MAX_PENDING = 3;
    static constexpr std::chrono::seconds LIFETIME{120};

    struct request {
        std::string id;      // 32 hex characters
        std::string code;    // "123 456", shown in the popup and in the app
        std::string browser; // name the extension gave
        std::string origin;  // extension origin
    };
    enum class state { pending, approved, denied, expired, unknown };

    // Called with the broker unlocked; may run on any thread.
    std::function<void(const request&)> on_open;
    std::function<void(const std::string& id)> on_close; // answered, expired or abandoned

    // nullopt when MAX_PENDING requests are already waiting.
    std::optional<request> open(const std::string& browser, const std::string& origin);
    // Expires the request when its lifetime is over.
    state status(const std::string& id);
    // The user's answer; false if the request is unknown or no longer pending.
    bool answer(const std::string& id, bool approve);
    // Drops the request (its session took the result or went away).
    void forget(const std::string& id);
    std::vector<request> pending() const;

private:
    struct entry {
        request req;
        state st = state::pending;
        std::chrono::steady_clock::time_point expires;
    };
    mutable std::mutex m_mutex;
    std::map<std::string, entry> m_requests;
};

// What a session needs from the application.
struct browser_hooks {
    // Runs `job` on the vault worker thread and returns when it is done.
    // (Tests run it inline.)
    std::function<void(const std::function<void()>& job)> run_on_worker;
    // Puts a generated password on the clipboard, cleared after the delay.
    std::function<bool(secure_string&& text, std::chrono::seconds clear_after)> copy_to_clipboard;
    std::function<void()> on_vault_unlocked; // unlocked from the browser
    std::function<void()> on_vault_locked;   // locked from the browser
    std::function<void()> on_activity;       // any authenticated request
    // RFC 3339 UTC "now" (tests may pin it).
    std::function<std::string()> now;
};

// One connection from a native host. Not thread-safe: the connection thread
// feeds it requests one at a time; vault access goes through run_on_worker.
class browser_session {
public:
    browser_session(vault_store& store, vault_bridge& bridge, browser_pairings& pairings,
                    pairing_broker& broker, browser_hooks hooks, std::vector<std::string> allowed_origins);
    ~browser_session();

    browser_session(const browser_session&) = delete;
    browser_session& operator=(const browser_session&) = delete;

    // One JSON request in, one JSON reply out. The request text is wiped.
    std::string handle(std::string& request);

    // After repeated authentication failures the connection must be closed.
    bool should_close() const { return m_auth_failures >= MAX_AUTH_FAILURES; }

    // Byte strings both sides sign (exposed for tests and the docs):
    //   proof       = HMAC-SHA256(key, "phylaxbox-browser-auth-v1\0client\0" || server_challenge || client_challenge)
    //   serverProof = HMAC-SHA256(key, "phylaxbox-browser-auth-v1\0server\0" || server_challenge || client_challenge)
    static secure_string auth_message(bool client, const secure_string& server_challenge,
                                      const secure_string& client_challenge);

private:
    static constexpr int MAX_AUTH_FAILURES = 3;

    secure_json dispatch(const std::string& type, const secure_json& req);
    secure_json hello(const secure_json& req);
    secure_json pair_begin(const secure_json& req);
    secure_json pair_status(const secure_json& req);
    secure_json auth_begin(const secure_json& req);
    secure_json auth_finish(const secure_json& req);
    secure_json vault_status();
    secure_json unlock(const secure_json& req);
    secure_json lock();
    secure_json matches(const secure_json& req);
    secure_json search(const secure_json& req);
    secure_json credentials(const secure_json& req);
    secure_json generate(const secure_json& req);
    secure_json on_worker(const std::function<secure_json()>& job);

    vault_store& m_store;
    vault_bridge& m_bridge;
    browser_pairings& m_pairings;
    pairing_broker& m_broker;
    browser_hooks m_hooks;
    std::vector<std::string> m_allowed_origins;

    std::string m_origin;              // set by hello
    std::optional<std::string> m_pairing_id;
    std::string m_pairing_browser;
    std::string m_challenge_client;    // client id the challenge was issued to
    secure_string m_server_challenge;
    std::string m_authenticated;       // client id once authenticated
    int m_auth_failures = 0;
};

} // namespace pb::app

#endif // PB_BROWSER_PROTOCOL_H_
