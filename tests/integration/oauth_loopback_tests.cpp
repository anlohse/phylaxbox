#include "dropbox_link.h"
#include "sync/dropbox_oauth.h"
#include "fake_transport.h"
#include "httplib_transport.h"
#include "oauth_loopback.h"
#include "models/pbexceptions.h"

#include <gtest/gtest.h>
#include <httplib.h>

#include <future>
#include <thread>

using namespace pb::app;
using pb_test::fake_transport;
using pb_test::parse_form;

namespace {

httplib::Result get(int port, const std::string& path_and_query) {
    httplib::Client cli("127.0.0.1", port);
    cli.set_connection_timeout(5);
    return cli.Get(path_and_query);
}

std::string callback(const std::string& query) {
    return std::string(oauth_loopback_receiver::CALLBACK_PATH) + "?" + query;
}

} // namespace

TEST(OAuthLoopback, ReturnsCodeForMatchingState) {
    oauth_loopback_receiver r(0);
    r.start("good-state");
    ASSERT_GT(r.port(), 0);
    EXPECT_EQ(r.redirect_uri(),
              "http://127.0.0.1:" + std::to_string(r.port()) + "/phylaxbox/callback");

    auto wrong = get(r.port(), callback("code=evil&state=bad-state"));
    ASSERT_TRUE(wrong);
    EXPECT_EQ(wrong->status, 400);

    auto missing = get(r.port(), callback("code=evil"));
    ASSERT_TRUE(missing);
    EXPECT_EQ(missing->status, 400);

    auto ok = get(r.port(), callback("code=the-code&state=good-state"));
    ASSERT_TRUE(ok);
    EXPECT_EQ(ok->status, 200);
    EXPECT_EQ(ok->get_header_value("Cache-Control"), "no-store");

    EXPECT_EQ(r.wait_for_code(std::chrono::seconds(5)), "the-code");

    auto again = get(r.port(), callback("code=second&state=good-state"));
    ASSERT_TRUE(again);
    EXPECT_EQ(again->status, 409);
}

TEST(OAuthLoopback, UserDeniedAccess) {
    oauth_loopback_receiver r(0);
    r.start("s");
    auto res = get(r.port(), callback("error=access_denied&state=s"));
    ASSERT_TRUE(res);
    EXPECT_THROW(r.wait_for_code(std::chrono::seconds(5)), authentication_exception);
}

TEST(OAuthLoopback, Timeout) {
    oauth_loopback_receiver r(0);
    r.start("s");
    try {
        r.wait_for_code(std::chrono::seconds(1));
        FAIL() << "expected timeout";
    } catch (const pbexception& e) {
        EXPECT_EQ(e.errorcode(), ErrorCodes::OAUTH_TIMEOUT);
    }
}

TEST(OAuthLoopback, StopRightAfterStartDoesNotHang) {
    for (int i = 0; i < 20; ++i) {
        oauth_loopback_receiver r(0);
        r.start("s");
    } // destructor stops immediately
}

// Another process must not be able to bind the same port and intercept the
// redirect (cpp-httplib's default SO_REUSEADDR would allow it on Windows).
TEST(OAuthLoopback, PortInUseIsReported) {
    oauth_loopback_receiver first(0);
    first.start("s");
    oauth_loopback_receiver second(first.port());
    EXPECT_THROW(second.start("s"), pbexception);
}

// End-to-end link flow: real loopback listener, simulated browser, fake
// Dropbox token endpoint.
TEST(DropboxLink, FullFlow) {
    fake_transport http;
    http.token("access", 14400, "the-refresh-token");

    std::thread browser;
    std::string seen_url;
    auto open_browser = [&](const std::string& url) {
        seen_url = url;
        const auto q = parse_form(url.substr(url.find('?') + 1));
        const auto redirect = q.at("redirect_uri");
        const int port = std::stoi(redirect.substr(redirect.rfind(':') + 1));
        const std::string state = q.at("state");
        // The "user" approves in the browser, Dropbox redirects back.
        browser = std::thread([port, state] {
            get(port, callback("code=auth-code&state=" + state));
        });
        return true;
    };

    const std::string refresh =
        link_dropbox(http, "app-key", open_browser, 0, std::chrono::seconds(10));
    browser.join();

    EXPECT_EQ(refresh, "the-refresh-token");
    ASSERT_EQ(http.requests.size(), 1u);
    const auto f = parse_form(http.requests[0].body);
    EXPECT_EQ(f.at("code"), "auth-code");
    // The verifier sent to the token endpoint matches the challenge in the URL.
    const auto q = parse_form(seen_url.substr(seen_url.find('?') + 1));
    EXPECT_EQ(pb::sync::dropbox::pkce_pair::challenge_for(f.at("code_verifier")),
              q.at("code_challenge"));
    EXPECT_EQ(f.at("redirect_uri"), q.at("redirect_uri"));
}

TEST(DropboxLink, RequiresAppKey) {
    fake_transport http;
    EXPECT_THROW(link_dropbox(http, "", [](const std::string&) { return true; }, 0),
                 pbexception);
}

TEST(OpenBrowser, RefusesNonHttpsUrls) {
    EXPECT_FALSE(open_in_default_browser("file:///C:/Windows/System32/calc.exe"));
    EXPECT_FALSE(open_in_default_browser("calc.exe"));
}

// Real httplib transport against a local plain-HTTP server.
TEST(HttplibTransport, PostAndHeaderNormalization) {
    httplib::Server server;
    server.Post("/echo", [](const httplib::Request& req, httplib::Response& res) {
        res.set_header("X-Mixed-Case", "yes");
        res.status = 201;
        res.set_content(req.get_header_value("X-Arg") + "|" + req.get_header_value("Content-Type") +
                            "|" + req.body,
                        "text/plain");
    });
    const int port = server.bind_to_any_port("127.0.0.1");
    std::thread t([&] { server.listen_after_bind(); });

    httplib_transport transport;
    pb::sync::http_request req;
    req.base_url = "http://127.0.0.1:" + std::to_string(port);
    req.path = "/echo";
    req.headers = {{"X-Arg", "value"}};
    req.body = std::string("a\0b", 3);
    req.content_type = "application/octet-stream";
    const auto res = transport.post(req);

    server.stop();
    t.join();

    EXPECT_EQ(res.status, 201);
    EXPECT_EQ(res.header("x-mixed-case"), "yes");
    EXPECT_EQ(res.body, std::string("value|application/octet-stream|a\0b", 34));
}

TEST(HttplibTransport, ConnectionRefusedIsNetworkError) {
    // Bind then close to get a port that is very likely free.
    int port = 0;
    {
        httplib::Server s;
        port = s.bind_to_any_port("127.0.0.1");
    }
    httplib_transport transport(std::chrono::seconds(2), std::chrono::seconds(2));
    pb::sync::http_request req;
    req.base_url = "http://127.0.0.1:" + std::to_string(port);
    req.path = "/";
    EXPECT_THROW(transport.post(req), network_exception);
}
