#ifndef PB_OAUTH_LOOPBACK_H_
#define PB_OAUTH_LOOPBACK_H_

#include <chrono>
#include <memory>
#include <string>

namespace pb::app {

// One-shot HTTP listener on 127.0.0.1 that receives the OAuth redirect
// (RFC 8252 "loopback interface redirection").
//  * binds only to the loopback interface, never 0.0.0.0;
//  * ignores callbacks whose `state` does not match (CSRF / stray requests);
//  * completes on the first callback carrying the right state.
class oauth_loopback_receiver {
public:
    static constexpr const char* CALLBACK_PATH = "/phylaxbox/callback";

    // port 0 picks a free port (tests). Production uses LOCAL_PORT, which
    // must match the redirect URI registered in the Dropbox app console.
    explicit oauth_loopback_receiver(int port);
    ~oauth_loopback_receiver();

    oauth_loopback_receiver(const oauth_loopback_receiver&) = delete;
    oauth_loopback_receiver& operator=(const oauth_loopback_receiver&) = delete;

    // Binds and starts listening in a background thread. Throws
    // pbexception(NETWORK_ERROR) if the port is unavailable.
    void start(const std::string& expected_state);

    int port() const;
    std::string redirect_uri() const;

    // Blocks until the redirect arrives. Returns the authorization code.
    // Throws authentication_exception if the user denied access and
    // pbexception(OAUTH_TIMEOUT) on timeout.
    std::string wait_for_code(std::chrono::seconds timeout);

    void stop();

private:
    struct impl;
    std::unique_ptr<impl> m;
};

} // namespace pb::app

#endif // PB_OAUTH_LOOPBACK_H_
