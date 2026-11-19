// End to end without a browser: the extension's messages go through the
// native host relay, the real local IPC channel and the app's browser
// service, as they do in production (only stdin/stdout are replaced).
#include "browser_pairings.h"
#include "browser_protocol.h"
#include "browser_service.h"
#include "relay.h"
#include "serial_worker.h"
#include "test_helpers.h"
#include "vault_bridge.h"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <sodium.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <future>
#include <mutex>
#include <string>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

using json = nlohmann::json;
using pb_test::temp_dir;

namespace {

const std::string kChrome = "chrome-extension://glegncflenphgoeiohlifdmibnfdefaf/";
const std::string kPassword = "correct horse battery";

std::string test_endpoint(const temp_dir& dir) {
    static std::atomic<int> counter{0};
#ifdef _WIN32
    (void)dir;
    return "\\\\.\\pipe\\phylaxbox.test.host." + std::to_string(::GetCurrentProcessId()) + "." +
           std::to_string(counter++);
#else
    const auto sockets = dir.path() / ("ipc" + std::to_string(counter++));
    std::filesystem::create_directories(sockets);
    ::chmod(sockets.c_str(), 0700);
    return (sockets / "browser.sock").string();
#endif
}

std::string b64(const std::string& raw) {
    std::string out(sodium_base64_ENCODED_LEN(raw.size(), sodium_base64_VARIANT_ORIGINAL), '\0');
    sodium_bin2base64(out.data(), out.size(), reinterpret_cast<const unsigned char*>(raw.data()), raw.size(),
                      sodium_base64_VARIANT_ORIGINAL);
    out.pop_back();
    return out;
}

std::string unb64(const std::string& text) {
    std::string out(text.size(), '\0');
    std::size_t len = 0;
    sodium_base642bin(reinterpret_cast<unsigned char*>(out.data()), out.size(), text.data(), text.size(), nullptr,
                      &len, nullptr, sodium_base64_VARIANT_ORIGINAL);
    out.resize(len);
    return out;
}

std::string hmac(const std::string& key, const pb::secure_string& message) {
    std::string out(crypto_auth_hmacsha256_BYTES, '\0');
    crypto_auth_hmacsha256(reinterpret_cast<unsigned char*>(out.data()),
                           reinterpret_cast<const unsigned char*>(message.data()), message.size(),
                           reinterpret_cast<const unsigned char*>(key.data()));
    return out;
}

// The browser side of the native host: messages in, replies out.
class fake_browser {
public:
    fake_browser(std::string origin, std::string endpoint)
        : m_relay(std::move(origin), std::move(endpoint), [this] { return ++launches, true; }) {
        m_thread = std::thread([this] {
            m_relay.run({[this] { return next_message(); },
                         [this](const std::string& reply) {
                             std::lock_guard<std::mutex> lock(m_mutex);
                             m_replies.push_back(json::parse(reply));
                             m_cv.notify_all();
                             return true;
                         }});
        });
    }

    ~fake_browser() {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_closed = true; // the browser closes the port
        }
        m_cv.notify_all();
        m_thread.join();
    }

    // Sends a request and waits for the reply with the same id.
    json request(json message) {
        const std::uint64_t id = ++m_next_id;
        message["id"] = id;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_inbox.push_back(message.dump());
        }
        m_cv.notify_all();
        std::unique_lock<std::mutex> lock(m_mutex);
        json found;
        const bool got = m_cv.wait_for(lock, std::chrono::seconds(20), [&] {
            for (auto it = m_replies.begin(); it != m_replies.end(); ++it) {
                if (it->value("id", std::uint64_t{0}) == id) {
                    found = *it;
                    m_replies.erase(it);
                    return true;
                }
            }
            return false;
        });
        EXPECT_TRUE(got) << "no reply to " << message.dump();
        return found;
    }

    int launches = 0;

private:
    std::optional<std::string> next_message() {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_cv.wait(lock, [this] { return m_closed || !m_inbox.empty(); });
        if (m_inbox.empty()) return std::nullopt;
        std::string m = std::move(m_inbox.front());
        m_inbox.pop_front();
        return m;
    }

    pb::host::relay m_relay;
    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::deque<std::string> m_inbox;
    std::deque<json> m_replies;
    bool m_closed = false;
    std::uint64_t m_next_id = 0;
    std::thread m_thread;
};

// The desktop app's side: vault, worker thread and browser service.
struct desktop {
    temp_dir dir;
    std::string endpoint = test_endpoint(dir);
    pb::vault_store store{dir.path() / "vault.phylaxbox", pb_test::fast_kdf()};
    pb::app::vault_bridge bridge{store, "0b6e1c1a-3f5d-4a8e-9c2b-7d4e5f6a7b8c", dir.path() / "settings.json"};
    pb::app::browser_pairings pairings{dir.path() / "browser-pairings.json"};
    pb::app::serial_worker worker;
    std::mutex mutex;
    std::vector<pb::app::pairing_broker::request> requests;
    std::unique_ptr<pb::app::browser_service> service;

    desktop() {
        bridge.create(json::array({kPassword, false}).dump());
        json fields = {{"title", "Bank"},
                       {"username", "alice"},
                       {"password", "bank-secret"},
                       {"urls", json::array({"https://bank.example.com"})}};
        bridge.add(json::array({fields}).dump());
        start();
    }
    ~desktop() {
        if (service) service->stop();
        worker.stop();
    }

    void start() {
        pb::app::browser_hooks hooks;
        hooks.run_on_worker = [this](const std::function<void()>& job) {
            std::promise<void> done;
            if (!worker.post([&] {
                    job();
                    done.set_value();
                })) {
                return;
            }
            done.get_future().wait();
        };
        pb::app::browser_service::ui_hooks ui;
        ui.on_pairing_request = [this](const pb::app::pairing_broker::request& r) {
            std::lock_guard<std::mutex> lock(mutex);
            requests.push_back(r);
        };
        service = std::make_unique<pb::app::browser_service>(store, bridge, pairings, hooks,
                                                             std::vector<std::string>{kChrome}, ui);
        ASSERT_TRUE(service->start(endpoint));
    }

    // What the user does in the app's pairing dialog.
    void approve_last() {
        std::string id;
        {
            std::lock_guard<std::mutex> lock(mutex);
            ASSERT_FALSE(requests.empty());
            id = requests.back().id;
        }
        const auto reply = json::parse(service->pair_answer(json::array({id, true}).dump()));
        EXPECT_EQ(reply.at("ok"), true) << reply.dump();
    }
};

// Pairing + authentication as the extension does it. Returns {clientId, key}.
std::pair<std::string, std::string> pair_and_authenticate(fake_browser& b, desktop& d) {
    const json begin = b.request({{"type", "pair_begin"}, {"browser", "Chrome"}});
    EXPECT_EQ(begin.at("ok"), true) << begin.dump();
    EXPECT_EQ(b.request({{"type", "pair_status"}, {"pairingId", begin.at("pairingId")}}).at("state"), "pending");
    d.approve_last();
    const json done = b.request({{"type", "pair_status"}, {"pairingId", begin.at("pairingId")}});
    EXPECT_EQ(done.at("state"), "approved") << done.dump();
    const std::string client_id = done.at("clientId");
    const std::string key = unb64(done.at("key"));
    EXPECT_EQ(b.request({{"type", "status"}}).at("code"), "not_authenticated");

    const json challenge = b.request({{"type", "auth_begin"}, {"clientId", client_id}});
    const std::string server_challenge = unb64(challenge.at("challenge"));
    const std::string client_challenge(32, 'z');
    const std::string proof = hmac(key, pb::app::browser_session::auth_message(
                                            true, pb::to_secure(server_challenge), pb::to_secure(client_challenge)));
    const json finish = b.request({{"type", "auth_finish"},
                                   {"clientId", client_id},
                                   {"clientChallenge", b64(client_challenge)},
                                   {"proof", b64(proof)}});
    EXPECT_EQ(finish.at("ok"), true) << finish.dump();
    return {client_id, key};
}

} // namespace

TEST(NativeHost, AnswersLocallyWithoutTheApp) {
    temp_dir dir;
    fake_browser browser(kChrome, test_endpoint(dir));
    const json ping = browser.request({{"type", "ping"}});
    EXPECT_EQ(ping.at("ok"), true);
    EXPECT_EQ(ping.at("protocol"), 1);
    EXPECT_EQ(browser.request({{"type", "status"}}).at("code"), "app_unavailable") << "fails closed";
    EXPECT_EQ(browser.request({{"type", "hello"}, {"protocol", 1}, {"origin", kChrome}}).at("code"), "unknown_type")
        << "the extension cannot choose the origin";
    EXPECT_EQ(browser.request({{"type", "exec"}, {"cmd", "calc"}}).at("code"), "unknown_type");
    EXPECT_EQ(browser.request({{"type", "launch_app"}}).at("ok"), true);
    EXPECT_EQ(browser.launches, 1);
}

TEST(NativeHost, ExtensionOriginIsChecked) {
    desktop app;
    fake_browser browser("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/", app.endpoint);
    EXPECT_EQ(browser.request({{"type", "pair_begin"}, {"browser", "Chrome"}}).at("code"), "origin_not_allowed");
}

TEST(NativeHost, PairAuthenticateAndFill) {
    desktop app;
    fake_browser browser(kChrome, app.endpoint);
    pair_and_authenticate(browser, app);

    EXPECT_EQ(browser.request({{"type", "lock"}}).at("ok"), true);
    EXPECT_EQ(browser.request({{"type", "matches"}, {"url", "https://bank.example.com/"}}).at("code"), "locked");
    EXPECT_EQ(browser.request({{"type", "unlock"}, {"password", kPassword}}).at("ok"), true);

    const json matches = browser.request({{"type", "matches"}, {"url", "https://login.bank.example.com/"}});
    ASSERT_EQ(matches.at("entries").size(), 1u) << matches.dump();
    const std::string entry_id = matches.at("entries")[0].at("id");
    const json creds =
        browser.request({{"type", "credentials"}, {"entryId", entry_id}, {"url", "https://login.bank.example.com/"}});
    EXPECT_EQ(creds.at("username"), "alice");
    EXPECT_EQ(creds.at("password"), "bank-secret");
}

TEST(NativeHost, AppRestartNeedsANewAuthentication) {
    desktop app;
    fake_browser browser(kChrome, app.endpoint);
    const auto [client_id, key] = pair_and_authenticate(browser, app);
    EXPECT_EQ(browser.request({{"type", "status"}}).at("ok"), true);

    app.service->stop(); // the app quits
    EXPECT_EQ(browser.request({{"type", "status"}}).at("code"), "app_unavailable");

    app.start(); // and comes back
    EXPECT_EQ(browser.request({{"type", "status"}}).at("code"), "not_authenticated")
        << "a new connection is a new session";
    EXPECT_TRUE(app.pairings.find(client_id)) << "the pairing itself survives";
}
