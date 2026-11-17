#include "oauth_loopback.h"

#include "models/pbexceptions.h"

#include <httplib.h>
#include <sodium.h>

#include <condition_variable>
#include <mutex>
#include <thread>

namespace pb::app {

namespace {

const char* PAGE_OK =
    "<!doctype html><meta charset=utf-8><title>PhylaxBox</title>"
    "<body style=\"font-family:sans-serif;text-align:center;margin-top:4em\">"
    "<h1>PhylaxBox conectado</h1><p>Voc\xC3\xAA j\xC3\xA1 pode fechar esta janela.</p>";

const char* PAGE_DENIED =
    "<!doctype html><meta charset=utf-8><title>PhylaxBox</title>"
    "<body style=\"font-family:sans-serif;text-align:center;margin-top:4em\">"
    "<h1>Acesso n\xC3\xA3o autorizado</h1><p>Volte ao PhylaxBox para tentar de novo.</p>";

bool same_string(const std::string& a, const std::string& b) {
    return a.size() == b.size() && sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}

} // namespace

struct oauth_loopback_receiver::impl {
    int requested_port;
    int bound_port = 0;
    std::string expected_state;
    httplib::Server server;
    std::thread thread;

    std::mutex mutex;
    std::condition_variable cv;
    bool done = false;
    std::string code;
    std::string error;
};

oauth_loopback_receiver::oauth_loopback_receiver(int port) : m(std::make_unique<impl>()) {
    m->requested_port = port;
}

oauth_loopback_receiver::~oauth_loopback_receiver() { stop(); }

void oauth_loopback_receiver::start(const std::string& expected_state) {
    m->expected_state = expected_state;
    m->server.Get(CALLBACK_PATH, [this](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Cache-Control", "no-store");
        res.set_header("Referrer-Policy", "no-referrer");
        const std::string state = req.get_param_value("state");
        if (state.empty() || !same_string(state, m->expected_state)) {
            res.status = 400;
            res.set_content("invalid state", "text/plain");
            return; // keep waiting for the genuine redirect
        }
        std::lock_guard<std::mutex> lock(m->mutex);
        if (m->done) {
            res.status = 409;
            res.set_content("already completed", "text/plain");
            return;
        }
        if (req.has_param("code")) {
            m->code = req.get_param_value("code");
            res.set_content(PAGE_OK, "text/html; charset=utf-8");
        } else {
            m->error = req.has_param("error") ? req.get_param_value("error") : "no code";
            res.status = 400;
            res.set_content(PAGE_DENIED, "text/html; charset=utf-8");
        }
        m->done = true;
        m->cv.notify_all();
    });

    // cpp-httplib's default sets SO_REUSEADDR, which on Windows lets another
    // process bind the same port and intercept the redirect. Claim it exclusively.
    m->server.set_socket_options([](auto sock) {
#ifdef _WIN32
        const int on = 1;
        ::setsockopt(sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&on),
                     sizeof(on));
#else
        const int on = 1;
        ::setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)); // safe on POSIX
#endif
    });

    const char* host = "127.0.0.1";
    if (m->requested_port == 0) {
        m->bound_port = m->server.bind_to_any_port(host);
    } else if (m->server.bind_to_port(host, m->requested_port)) {
        m->bound_port = m->requested_port;
    }
    if (m->bound_port <= 0) {
        throw pbexception(ErrorCodes::NETWORK_ERROR,
                          "cannot listen on 127.0.0.1:" + std::to_string(m->requested_port));
    }
    m->thread = std::thread([this] { m->server.listen_after_bind(); });
    // Server::stop() is a no-op until the listen loop is running; without this
    // wait, an early stop() would leave the thread blocked in accept() forever.
    m->server.wait_until_ready();
}

int oauth_loopback_receiver::port() const { return m->bound_port; }

std::string oauth_loopback_receiver::redirect_uri() const {
    return "http://127.0.0.1:" + std::to_string(m->bound_port) + CALLBACK_PATH;
}

std::string oauth_loopback_receiver::wait_for_code(std::chrono::seconds timeout) {
    std::unique_lock<std::mutex> lock(m->mutex);
    if (!m->cv.wait_for(lock, timeout, [this] { return m->done; })) {
        throw pbexception(ErrorCodes::OAUTH_TIMEOUT, "no answer from the browser");
    }
    if (!m->error.empty()) {
        throw authentication_exception(ErrorCodes::UNAUTHORIZED, m->error);
    }
    return m->code;
}

void oauth_loopback_receiver::stop() {
    if (!m) return;
    m->server.stop();
    if (m->thread.joinable()) {
        m->thread.join();
    }
}

} // namespace pb::app
