#include "sync/dropbox_oauth.h"
#include "sync/dropbox_storage.h"
#include "fake_transport.h"
#include "models/pbexceptions.h"
#include "sync/storage_factory.h"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <regex>

using namespace pb::sync;
using pb_test::fake_transport;
using pb_test::parse_form;
using json = nlohmann::json;

namespace {

const std::string kAppKey = "app-key-123";
const std::string kRefresh = "refresh-abc";

template <typename E>
int code_of(const std::function<void()>& f) {
    try {
        f();
    } catch (const E& e) {
        return e.errorcode();
    }
    ADD_FAILURE() << "expected exception was not thrown";
    return 0;
}

json api_arg(const http_request& r) {
    return json::parse(fake_transport::header(r, "Dropbox-API-Arg"));
}

// Controllable clock for token expiry.
struct fake_clock {
    std::chrono::steady_clock::time_point now{};
    dropbox_storage::clock_fn fn() {
        return [this] { return now; };
    }
};

} // namespace

// ---------------------------------------------------------------------------
// OAuth helpers
// ---------------------------------------------------------------------------

TEST(DropboxOAuth, PkceVerifierShapeAndChallenge) {
    const auto p = dropbox::pkce_pair::generate();
    EXPECT_EQ(p.verifier.size(), 43u); // RFC 7636: 43..128
    EXPECT_TRUE(std::regex_match(p.verifier, std::regex("[A-Za-z0-9_-]+")));
    EXPECT_EQ(p.challenge, dropbox::pkce_pair::challenge_for(p.verifier));
    EXPECT_NE(p.verifier, dropbox::pkce_pair::generate().verifier);

    // Expected value computed independently with Python:
    //   base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b'=')
    EXPECT_EQ(dropbox::pkce_pair::challenge_for("dBjftJeZ4CVP-mJ92K9b9tamk2hIuOEdEe5Q2ijx08Q"),
              "LARZxEz4DbbwKT-fiQIkiRgKWsHCc6tgE6R33KQsL3w");
}

TEST(DropboxOAuth, UrlEncode) {
    EXPECT_EQ(dropbox::url_encode("AZaz09-._~"), "AZaz09-._~");
    EXPECT_EQ(dropbox::url_encode("http://127.0.0.1:8881/a b"),
              "http%3A%2F%2F127.0.0.1%3A8881%2Fa%20b");
    EXPECT_EQ(dropbox::url_encode("\xC3\xA4"), "%C3%A4");
}

TEST(DropboxOAuth, AuthorizeUrl) {
    dropbox::pkce_pair p{"verifier", "challenge"};
    const auto url = dropbox::build_authorize_url(kAppKey, "http://127.0.0.1:8881/cb", p, "st");
    ASSERT_EQ(url.rfind("https://www.dropbox.com/oauth2/authorize?", 0), 0u);
    const auto q = parse_form(url.substr(url.find('?') + 1));
    EXPECT_EQ(q.at("client_id"), kAppKey);
    EXPECT_EQ(q.at("response_type"), "code");
    EXPECT_EQ(q.at("token_access_type"), "offline");
    EXPECT_EQ(q.at("code_challenge"), "challenge");
    EXPECT_EQ(q.at("code_challenge_method"), "S256");
    EXPECT_EQ(q.at("redirect_uri"), "http://127.0.0.1:8881/cb");
    EXPECT_EQ(q.at("state"), "st");
    EXPECT_EQ(url.find("verifier"), std::string::npos); // the verifier never leaves the app
}

TEST(DropboxOAuth, ExchangeCode) {
    fake_transport http;
    http.token("access-1", 14400, kRefresh);
    const auto t = dropbox::exchange_code(http, kAppKey, "the-code", "the-verifier", "http://r");

    EXPECT_EQ(t.access_token, "access-1");
    EXPECT_EQ(t.refresh_token, kRefresh);
    EXPECT_EQ(t.expires_in.count(), 14400);

    ASSERT_EQ(http.requests.size(), 1u);
    const auto& r = http.requests[0];
    EXPECT_EQ(r.base_url, "https://api.dropboxapi.com");
    EXPECT_EQ(r.path, "/oauth2/token");
    EXPECT_EQ(r.content_type, "application/x-www-form-urlencoded");
    const auto f = parse_form(r.body);
    EXPECT_EQ(f.at("grant_type"), "authorization_code");
    EXPECT_EQ(f.at("code"), "the-code");
    EXPECT_EQ(f.at("code_verifier"), "the-verifier");
    EXPECT_EQ(f.at("client_id"), kAppKey);
    EXPECT_EQ(f.at("redirect_uri"), "http://r");
    EXPECT_EQ(f.count("client_secret"), 0u);
}

TEST(DropboxOAuth, ExchangeCodeErrors) {
    fake_transport http;
    http.respond(400, R"({"error":"invalid_grant","error_description":"code doesn't exist"})");
    EXPECT_EQ(code_of<authentication_exception>([&] {
                  dropbox::exchange_code(http, kAppKey, "c", "v", "r");
              }),
              ErrorCodes::UNAUTHORIZED);

    http.token("access-only"); // no refresh token: offline access missing
    EXPECT_THROW(dropbox::exchange_code(http, kAppKey, "c", "v", "r"), http_exception);

    http.respond(200, "not json");
    EXPECT_THROW(dropbox::exchange_code(http, kAppKey, "c", "v", "r"), http_exception);
}

TEST(DropboxOAuth, RevokedRefreshTokenMeansNotLinked) {
    fake_transport http;
    http.respond(400, R"({"error":"invalid_grant"})");
    EXPECT_EQ(code_of<authentication_exception>([&] {
                  dropbox::refresh_access_token(http, kAppKey, kRefresh);
              }),
              ErrorCodes::NOT_LINKED);
    EXPECT_EQ(code_of<authentication_exception>([&] {
                  dropbox::refresh_access_token(http, kAppKey, "");
              }),
              ErrorCodes::NOT_LINKED);

    const auto f = parse_form(http.requests.at(0).body);
    EXPECT_EQ(f.at("grant_type"), "refresh_token");
    EXPECT_EQ(f.at("refresh_token"), kRefresh);
}

// ---------------------------------------------------------------------------
// dropbox_storage
// ---------------------------------------------------------------------------

TEST(DropboxStorage, DownloadReturnsDataAndRev) {
    fake_transport http;
    http.token("access-1")
        .respond(200, std::string("\x01\x02\x00\x03", 4),
                 {{"dropbox-api-result", R"({"name":"vault.pbx","rev":"015abc"})"}});
    dropbox_storage s(http, kAppKey, kRefresh);

    const auto f = s.download();
    ASSERT_TRUE(f.has_value());
    EXPECT_EQ(f->rev, "015abc");
    EXPECT_EQ(f->data, (std::vector<std::uint8_t>{1, 2, 0, 3}));

    ASSERT_EQ(http.requests.size(), 2u);
    const auto& r = http.requests[1];
    EXPECT_EQ(r.base_url, "https://content.dropboxapi.com");
    EXPECT_EQ(r.path, "/2/files/download");
    EXPECT_EQ(fake_transport::header(r, "Authorization"), "Bearer access-1");
    EXPECT_EQ(api_arg(r).at("path"), "/vault.pbx");
    EXPECT_TRUE(r.content_type.empty());
}

TEST(DropboxStorage, DownloadNotFound) {
    fake_transport http;
    http.token("a").respond(
        409, R"({"error_summary":"path/not_found/..","error":{".tag":"path","path":{".tag":"not_found"}}})");
    dropbox_storage s(http, kAppKey, kRefresh);
    EXPECT_FALSE(s.download().has_value());
}

TEST(DropboxStorage, UploadUpdatesExpectedRevision) {
    fake_transport http;
    http.token("a").respond(200, R"({"name":"vault.pbx","rev":"016def"})");
    dropbox_storage s(http, kAppKey, kRefresh);

    const std::vector<std::uint8_t> data = {9, 0, 8};
    EXPECT_EQ(s.upload(data, "015abc"), "016def");

    const auto& r = http.requests[1];
    EXPECT_EQ(r.path, "/2/files/upload");
    EXPECT_EQ(r.content_type, "application/octet-stream");
    EXPECT_EQ(r.body, std::string("\x09\x00\x08", 3));
    const auto arg = api_arg(r);
    EXPECT_EQ(arg.at("mode").at(".tag"), "update");
    EXPECT_EQ(arg.at("mode").at("update"), "015abc");
    EXPECT_EQ(arg.at("strict_conflict"), true);
    EXPECT_EQ(arg.at("autorename"), false);
}

TEST(DropboxStorage, FirstUploadUsesAddMode) {
    fake_transport http;
    http.token("a").respond(200, R"({"rev":"001"})");
    dropbox_storage s(http, kAppKey, kRefresh);
    s.upload(std::vector<std::uint8_t>{1}, "");
    EXPECT_EQ(api_arg(http.requests[1]).at("mode"), "add");
}

TEST(DropboxStorage, ConcurrentSaveIsAConflict) {
    fake_transport http;
    http.token("a").respond(
        409, R"({"error_summary":"path/conflict/file/..","error":{".tag":"path","reason":{".tag":"conflict"}}})");
    dropbox_storage s(http, kAppKey, kRefresh);
    EXPECT_THROW(s.upload(std::vector<std::uint8_t>{1}, "old-rev"), sync_conflict_exception);
}

TEST(DropboxStorage, AccessTokenIsReusedUntilExpiry) {
    fake_clock clock;
    fake_transport http;
    http.token("a1", 3600)
        .respond(409, R"({"error_summary":"path/not_found/"})")
        .respond(409, R"({"error_summary":"path/not_found/"})")
        .token("a2", 3600)
        .respond(409, R"({"error_summary":"path/not_found/"})");
    dropbox_storage s(http, kAppKey, kRefresh, dropbox_storage::DEFAULT_PATH, clock.fn());

    s.download();
    clock.now += std::chrono::minutes(30);
    s.download(); // still valid: no refresh
    clock.now += std::chrono::minutes(30); // within the 60 s safety margin
    s.download();

    ASSERT_TRUE(http.exhausted());
    EXPECT_EQ(fake_transport::header(http.requests[2], "Authorization"), "Bearer a1");
    EXPECT_EQ(fake_transport::header(http.requests[4], "Authorization"), "Bearer a2");
}

TEST(DropboxStorage, Unauthorized401RefreshesOnceAndRetries) {
    fake_transport http;
    http.token("stale")
        .respond(401, R"({"error_summary":"expired_access_token/"})")
        .token("fresh")
        .respond(200, R"({"rev":"002"})");
    dropbox_storage s(http, kAppKey, kRefresh);
    EXPECT_EQ(s.upload(std::vector<std::uint8_t>{1}, "001"), "002");
    EXPECT_EQ(fake_transport::header(http.requests[3], "Authorization"), "Bearer fresh");
    // Exactly one Authorization header on the retried request.
    int count = 0;
    for (const auto& h : http.requests[3].headers) count += h.first == "Authorization";
    EXPECT_EQ(count, 1);
}

TEST(DropboxStorage, PersistentUnauthorizedIsAnError) {
    fake_transport http;
    http.token("a").respond(401, "{}").token("b").respond(401, R"({"error_summary":"invalid_access_token/"})");
    dropbox_storage s(http, kAppKey, kRefresh);
    EXPECT_THROW(s.download(), authentication_exception);
}

TEST(DropboxStorage, ServerAndNetworkErrors) {
    fake_transport http;
    http.token("a").respond(429, R"({"error_summary":"too_many_write_operations/"})");
    dropbox_storage s(http, kAppKey, kRefresh);
    EXPECT_EQ(code_of<unavailability_exception>([&] { s.download(); }),
              ErrorCodes::TOO_MANY_REQUESTS);

    http.respond(503, "");
    EXPECT_THROW(s.download(), unavailability_exception);

    http.respond(400, "Error in call to API function \"files/download\": bad arg");
    EXPECT_THROW(s.download(), http_exception);

    http.fail_network();
    EXPECT_THROW(s.download(), network_exception);

    http.respond(200, "body-without-rev-header");
    EXPECT_THROW(s.download(), http_exception);
}

TEST(DropboxStorage, RemoveIsIdempotent) {
    fake_transport http;
    http.token("a")
        .respond(200, "{}")
        .respond(409, R"({"error_summary":"path_lookup/not_found/"})");
    dropbox_storage s(http, kAppKey, kRefresh);
    s.remove();
    s.remove();
    EXPECT_EQ(http.requests[1].path, "/2/files/delete_v2");
    EXPECT_EQ(json::parse(http.requests[1].body).at("path"), "/vault.pbx");
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

TEST(StorageFactory, SelectsEngine) {
    fake_transport http;
    PBConfiguration cfg;
    EXPECT_EQ(make_cloud_storage(cfg, http, kAppKey), nullptr);

    cfg.sync_engine = DROPBOX;
    EXPECT_EQ(code_of<authentication_exception>([&] { make_cloud_storage(cfg, http, kAppKey); }),
              ErrorCodes::NOT_LINKED);
    cfg.sync_token = kRefresh;
    EXPECT_NE(make_cloud_storage(cfg, http, kAppKey), nullptr);
    EXPECT_EQ(code_of<pbexception>([&] { make_cloud_storage(cfg, http, ""); }),
              ErrorCodes::NOT_IMPLEMENTED);

    cfg.sync_engine = G_DRIVE;
    EXPECT_EQ(code_of<pbexception>([&] { make_cloud_storage(cfg, http, kAppKey); }),
              ErrorCodes::NOT_IMPLEMENTED);
    EXPECT_TRUE(http.requests.empty()); // construction does no network I/O
}
