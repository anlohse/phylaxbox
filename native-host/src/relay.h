#ifndef PB_NATIVE_HOST_RELAY_H_
#define PB_NATIVE_HOST_RELAY_H_

#include "ipc/local_channel.h"

#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>

// The native messaging host (spec §9): relays the extension's requests to
// the desktop app over the local IPC channel and the replies back.
//
// It never stores or decrypts anything (spec §9.4). It checks the shape of
// each message (size, JSON object, numeric id, known type), opens the
// connection to the app with a hello that carries the extension origin the
// browser reported, and fails closed: when the app is not running or goes
// away, requests are answered with "app_unavailable".
namespace pb::host {

// Largest message accepted from the browser.
constexpr std::size_t MAX_BROWSER_MESSAGE = 64 * 1024;

class relay {
public:
    struct browser_io {
        // Blocks for the next message from the browser; nullopt at the end.
        std::function<std::optional<std::string>()> read;
        // Sends one message to the browser (the relay serializes calls).
        std::function<bool(const std::string&)> write;
    };

    // `origin`: the extension origin from the command line (see
    // origin_from_args). `launch_app` starts the desktop app.
    relay(std::string origin, std::string endpoint, std::function<bool()> launch_app);
    ~relay();

    // Runs until the browser closes the channel. Returns the exit code.
    int run(browser_io io);

    // Chrome passes "chrome-extension://<id>/" as the first argument;
    // Firefox passes the manifest path and then the add-on id.
    static std::string origin_from_args(int argc, char** argv);

private:
    void handle(std::string& message);
    void reply(const std::string& text);
    void reply_error(std::optional<std::uint64_t> id, const char* code, const char* message);
    // Connects and says hello. On failure returns the error code to report.
    std::optional<std::string> connect();
    void disconnect();
    void read_replies(std::shared_ptr<ipc::connection> conn);

    std::string m_origin;
    std::string m_endpoint;
    std::function<bool()> m_launch_app;
    browser_io m_io;

    std::mutex m_write_mutex; // browser writes
    std::mutex m_mutex;       // connection state below
    std::shared_ptr<ipc::connection> m_conn;
    bool m_conn_alive = false;
    std::set<std::uint64_t> m_pending; // forwarded, not yet answered
    std::thread m_reader;
};

} // namespace pb::host

#endif // PB_NATIVE_HOST_RELAY_H_
