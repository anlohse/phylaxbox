// Browser protocol on the desktop side: hello, pairing, HMAC authentication
// and the requests an authenticated extension may make.
#include "browser_pairings.h"
#include "browser_protocol.h"
#include "test_helpers.h"
#include "vault_bridge.h"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <sodium.h>

#include <chrono>
#include <string>
#include <vector>

using pb::app::browser_client;
using pb::app::browser_hooks;
using pb::app::browser_pairings;
using pb::app::browser_session;
using pb::app::pairing_broker;
using pb_test::fast_kdf;
using pb_test::temp_dir;
using json = nlohmann::json;

namespace {

const std::string kChrome = "chrome-extension://glegncflenphgoeiohlifdmibnfdefaf/";
const std::string kFirefox = "{2a1eb531-0b19-4eb0-9b8b-d9f2ea62df83}";
const std::string kPassword = "correct horse battery";

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

pb::secure_string sec(const std::string& s) { return pb::to_secure(s); }

struct fixture {
    temp_dir dir;
    pb::vault_store store{dir.path() / "vault.phylaxbox", fast_kdf()};
    std::vector<std::string> clipboard;
    pb::app::vault_bridge bridge{store, "0b6e1c1a-3f5d-4a8e-9c2b-7d4e5f6a7b8c", dir.path() / "settings.json",
                                 bridge_hooks()};
    browser_pairings pairings{dir.path() / "browser-pairings.json"};
    pairing_broker broker;
    std::vector<pairing_broker::request> opened;
    std::vector<std::string> closed;
    int unlocked_events = 0, locked_events = 0, activity = 0;

    fixture() {
        broker.on_open = [this](const pairing_broker::request& r) { opened.push_back(r); };
        broker.on_close = [this](const std::string& id) { closed.push_back(id); };
    }

    pb::app::vault_bridge::hooks bridge_hooks() {
        pb::app::vault_bridge::hooks h;
        h.copy_to_clipboard = [this](pb::secure_string&& text, std::chrono::seconds) {
            clipboard.emplace_back(text.data(), text.size());
            return true;
        };
        return h;
    }

    browser_hooks hooks() {
        browser_hooks h;
        h.copy_to_clipboard = [this](pb::secure_string&& text, std::chrono::seconds) {
            clipboard.emplace_back(text.data(), text.size());
            return true;
        };
        h.on_vault_unlocked = [this] { ++unlocked_events; };
        h.on_vault_locked = [this] { ++locked_events; };
        h.on_activity = [this] { ++activity; };
        h.now = [] { return std::string("2026-11-18T12:00:00.000Z"); };
        return h;
    }

    std::unique_ptr<browser_session> session() {
        return std::make_unique<browser_session>(store, bridge, pairings, broker, hooks(),
                                                 std::vector<std::string>{kChrome, kFirefox});
    }

    void create_vault() {
        const auto r = json::parse(bridge.create(json::array({kPassword, false}).dump()));
        ASSERT_EQ(r.at("ok"), true);
    }

    std::string add(const std::string& title, const std::string& user, const std::string& password,
                    std::vector<std::string> urls) {
        json fields = {{"title", title}, {"username", user}, {"password", password}, {"urls", urls}};
        const auto r = json::parse(bridge.add(json::array({fields}).dump()));
        EXPECT_EQ(r.at("ok"), true) << r.dump();
        return r.value("id", std::string());
    }
};

// Sends one request; checks the reply echoes the id and is ASCII JSON.
json send(browser_session& s, json request) {
    static std::uint64_t next_id = 1;
    const std::uint64_t id = next_id++;
    request["id"] = id;
    std::string text = request.dump();
    const std::string reply = s.handle(text);
    EXPECT_EQ(text.find_first_not_of('\0'), std::string::npos) << "the request must be wiped";
    for (unsigned char c : reply) EXPECT_LT(c, 0x80) << reply;
    json js = json::parse(reply);
    EXPECT_EQ(js.value("id", std::uint64_t{0}), id) << reply;
    return js;
}

json hello(browser_session& s, const std::string& origin = kChrome) {
    return send(s, {{"type", "hello"}, {"protocol", 1}, {"origin", origin}});
}

// Pairs through the broker (approving as the user would); returns {clientId, key}.
std::pair<std::string, std::string> pair(fixture& f, browser_session& s) {
    const json begin = send(s, {{"type", "pair_begin"}, {"browser", "Chrome"}});
    EXPECT_EQ(begin.at("ok"), true) << begin.dump();
    EXPECT_TRUE(f.broker.answer(begin.at("pairingId"), true));
    const json done = send(s, {{"type", "pair_status"}, {"pairingId", begin.at("pairingId")}});
    EXPECT_EQ(done.at("state"), "approved") << done.dump();
    return {done.at("clientId"), unb64(done.at("key"))};
}

json authenticate(browser_session& s, const std::string& client_id, const std::string& key) {
    const json begin = send(s, {{"type", "auth_begin"}, {"clientId", client_id}});
    if (!begin.value("ok", false)) return begin;
    const std::string server_challenge = unb64(begin.at("challenge"));
    const std::string client_challenge(32, 'c');
    const std::string proof =
        hmac(key, browser_session::auth_message(true, sec(server_challenge), sec(client_challenge)));
    json finish = send(s, {{"type", "auth_finish"},
                           {"clientId", client_id},
                           {"clientChallenge", b64(client_challenge)},
                           {"proof", b64(proof)}});
    if (finish.value("ok", false)) {
        const std::string expected =
            hmac(key, browser_session::auth_message(false, sec(server_challenge), sec(client_challenge)));
        EXPECT_EQ(unb64(finish.at("serverProof")), expected) << "the app proves it knows the key too";
    }
    return finish;
}

} // namespace

// The same vector is checked by the extension's JavaScript implementation
// (browser-extension/test/auth.test.mjs).
TEST(BrowserAuth, CrossImplementationVector) {
    std::string key, sc, cc;
    for (int i = 0; i < 32; ++i) {
        key.push_back(static_cast<char>(i));
        sc.push_back(static_cast<char>(0x40 + i));
        cc.push_back(static_cast<char>(0x80 + i));
    }
    auto hex = [](const std::string& raw) { return pb_test::to_hex(pb::byte_view(raw)); };
    EXPECT_EQ(hex(hmac(key, browser_session::auth_message(true, sec(sc), sec(cc)))),
              "96ca53dafe237e371c73e5ede1cb5da6f0c2092194ab00c17ea15086ba0f8aad");
    EXPECT_EQ(hex(hmac(key, browser_session::auth_message(false, sec(sc), sec(cc)))),
              "cb3216551e759e71382e261e2a1e6346fb89852ebc37fbda362526fff6486d19");
}

TEST(BrowserProtocol, HelloComesFirstAndChecksTheOrigin) {
    fixture f;
    auto s = f.session();
    EXPECT_EQ(send(*s, {{"type", "status"}}).at("code"), "hello_required");

    auto other = f.session();
    EXPECT_EQ(hello(*other, "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/").at("code"), "origin_not_allowed");
    const json old = send(*other, {{"type", "hello"}, {"protocol", 2}, {"origin", kChrome}});
    EXPECT_EQ(old.at("code"), "unsupported_protocol");
    EXPECT_EQ(old.at("protocol"), 1);

    const json ok = hello(*s);
    EXPECT_EQ(ok.at("ok"), true);
    EXPECT_EQ(ok.at("protocol"), 1);
    EXPECT_EQ(hello(*s).at("code"), "unknown_type") << "only once";
}

TEST(BrowserProtocol, MalformedRequests) {
    fixture f;
    auto s = f.session();
    std::string not_json = "{nope";
    EXPECT_EQ(json::parse(s->handle(not_json)).at("code"), "bad_request");
    std::string huge = "{\"type\":\"hello\",\"x\":\"" + std::string(70000, 'a') + "\"}";
    EXPECT_EQ(json::parse(s->handle(huge)).at("code"), "bad_request");
    hello(*s);
    EXPECT_EQ(send(*s, {{"type", "rm -rf"}}).at("code"), "unknown_type");
    EXPECT_EQ(send(*s, {{"type", 5}}).at("code"), "bad_request");
}

TEST(BrowserProtocol, NothingWithoutAuthentication) {
    fixture f;
    f.create_vault();
    auto s = f.session();
    hello(*s);
    for (const char* type : {"status", "unlock", "lock", "matches", "search", "credentials", "generate"}) {
        EXPECT_EQ(send(*s, {{"type", type}}).at("code"), "not_authenticated") << type;
    }
    EXPECT_EQ(f.activity, 0);
}

TEST(BrowserPairing, ApprovedInTheApp) {
    fixture f;
    auto s = f.session();
    hello(*s);
    const json begin = send(*s, {{"type", "pair_begin"}, {"browser", "Chrome<script>"}});
    ASSERT_EQ(begin.at("ok"), true);
    ASSERT_EQ(f.opened.size(), 1u);
    EXPECT_EQ(f.opened[0].code, begin.at("verificationCode").get<std::string>());
    EXPECT_EQ(f.opened[0].browser, "Chromescript") << "names are sanitized";
    EXPECT_EQ(f.opened[0].origin, kChrome);
    EXPECT_EQ(std::string(begin.at("verificationCode")).size(), 7u); // "123 456"

    EXPECT_EQ(send(*s, {{"type", "pair_status"}, {"pairingId", begin.at("pairingId")}}).at("state"), "pending");
    EXPECT_TRUE(f.broker.answer(begin.at("pairingId"), true));
    EXPECT_FALSE(f.broker.answer(begin.at("pairingId"), false)) << "answered once";
    const json done = send(*s, {{"type", "pair_status"}, {"pairingId", begin.at("pairingId")}});
    EXPECT_EQ(done.at("state"), "approved");
    EXPECT_EQ(unb64(done.at("key")).size(), 32u);

    const auto listed = f.pairings.list();
    ASSERT_EQ(listed.size(), 1u);
    EXPECT_EQ(listed[0].id, done.at("clientId").get<std::string>());
    EXPECT_EQ(listed[0].origin, kChrome);
    // Kept on disk for the next start.
    browser_pairings reloaded(f.dir.path() / "browser-pairings.json");
    ASSERT_TRUE(reloaded.find(done.at("clientId")));
    EXPECT_EQ(reloaded.find(done.at("clientId"))->key, listed[0].key);
}

TEST(BrowserPairing, DeniedOrAbandoned) {
    fixture f;
    auto s = f.session();
    hello(*s);
    const json begin = send(*s, {{"type", "pair_begin"}, {"browser", "Firefox"}});
    f.broker.answer(begin.at("pairingId"), false);
    EXPECT_EQ(send(*s, {{"type", "pair_status"}, {"pairingId", begin.at("pairingId")}}).at("code"), "pairing_denied");
    EXPECT_TRUE(f.pairings.list().empty());

    // A session that goes away withdraws its request from the app's window.
    const json again = send(*s, {{"type", "pair_begin"}, {"browser", "Firefox"}});
    s.reset();
    EXPECT_EQ(f.closed.back(), again.at("pairingId").get<std::string>());
    EXPECT_TRUE(f.broker.pending().empty());
}

TEST(BrowserPairing, LimitedPendingRequests) {
    fixture f;
    std::vector<std::unique_ptr<browser_session>> sessions;
    for (std::size_t i = 0; i < pairing_broker::MAX_PENDING; ++i) {
        sessions.push_back(f.session());
        hello(*sessions.back());
        EXPECT_EQ(send(*sessions.back(), {{"type", "pair_begin"}, {"browser", "Chrome"}}).at("ok"), true);
    }
    auto extra = f.session();
    hello(*extra);
    EXPECT_EQ(send(*extra, {{"type", "pair_begin"}, {"browser", "Chrome"}}).at("code"), "busy");
}

TEST(BrowserAuth, ChallengeResponse) {
    fixture f;
    auto s = f.session();
    hello(*s);
    const auto [client_id, key] = pair(f, *s);

    auto next = f.session(); // a later connection
    hello(*next);
    EXPECT_EQ(authenticate(*next, client_id, key).at("ok"), true);
    EXPECT_EQ(f.pairings.find(client_id)->last_used_at, "2026-11-18T12:00:00.000Z");
    EXPECT_EQ(send(*next, {{"type", "status"}}).at("ok"), true);
}

TEST(BrowserAuth, WrongKeyOrOrigin) {
    fixture f;
    auto s = f.session();
    hello(*s);
    const auto [client_id, key] = pair(f, *s);

    auto wrong = f.session();
    hello(*wrong);
    EXPECT_EQ(authenticate(*wrong, client_id, std::string(32, 'x')).at("code"), "auth_failed");
    EXPECT_EQ(send(*wrong, {{"type", "status"}}).at("code"), "not_authenticated");
    EXPECT_FALSE(wrong->should_close());
    authenticate(*wrong, client_id, std::string(32, 'x'));
    authenticate(*wrong, client_id, std::string(32, 'x'));
    EXPECT_TRUE(wrong->should_close()) << "three failures end the connection";

    // The key belongs to the Chrome extension: Firefox cannot use it.
    auto firefox = f.session();
    hello(*firefox, kFirefox);
    EXPECT_EQ(authenticate(*firefox, client_id, key).at("code"), "not_paired");

    auto unknown = f.session();
    hello(*unknown);
    EXPECT_EQ(authenticate(*unknown, std::string(32, '0'), key).at("code"), "not_paired");

    // A challenge is good for one attempt only.
    auto replay = f.session();
    hello(*replay);
    send(*replay, {{"type", "auth_begin"}, {"clientId", client_id}});
    EXPECT_EQ(send(*replay, {{"type", "auth_finish"},
                             {"clientId", client_id},
                             {"clientChallenge", b64(std::string(32, 'c'))},
                             {"proof", b64(std::string(32, 'p'))}})
                  .at("code"),
              "auth_failed");
    EXPECT_EQ(send(*replay, {{"type", "auth_finish"},
                             {"clientId", client_id},
                             {"clientChallenge", b64(std::string(32, 'c'))},
                             {"proof", b64(std::string(32, 'p'))}})
                  .at("code"),
              "auth_failed");
}

TEST(BrowserAuth, RevokedClientsAreCutOff) {
    fixture f;
    auto s = f.session();
    hello(*s);
    const auto [client_id, key] = pair(f, *s);
    ASSERT_EQ(authenticate(*s, client_id, key).at("ok"), true);
    ASSERT_TRUE(f.pairings.remove(client_id));
    EXPECT_EQ(send(*s, {{"type", "status"}}).at("code"), "not_paired");
    EXPECT_EQ(send(*s, {{"type", "status"}}).at("code"), "not_authenticated");
}

// --- requests -------------------------------------------------------------------

class BrowserRequests : public ::testing::Test {
protected:
    void SetUp() override {
        f.create_vault();
        bank = f.add("Bank", "alice", "bank-secret", {"https://www.bank.example.com/login"});
        mail = f.add("Mail", "alice@mail", "mail-secret", {"https://accounts.mail.example.org"});
        other = f.add("Other bank", "bob", "other-secret", {"https://bank.example.net"});
        s = f.session();
        hello(*s);
        const auto [id, key] = pair(f, *s);
        ASSERT_EQ(authenticate(*s, id, key).at("ok"), true);
    }

    fixture f;
    std::unique_ptr<browser_session> s;
    std::string bank, mail, other;
};

TEST_F(BrowserRequests, StatusLockAndUnlockFromTheBrowser) {
    EXPECT_EQ(send(*s, {{"type", "status"}}).at("unlocked"), true);
    EXPECT_EQ(send(*s, {{"type", "lock"}}).at("ok"), true);
    EXPECT_EQ(f.locked_events, 1);
    EXPECT_FALSE(f.store.is_unlocked());
    EXPECT_EQ(send(*s, {{"type", "matches"}, {"url", "https://bank.example.com/"}}).at("code"), "locked");

    EXPECT_EQ(send(*s, {{"type", "unlock"}, {"password", "wrong password"}}).at("code"), "wrong_password");
    EXPECT_EQ(f.unlocked_events, 0);
    EXPECT_EQ(send(*s, {{"type", "unlock"}, {"password", kPassword}}).at("ok"), true);
    EXPECT_EQ(f.unlocked_events, 1);
    EXPECT_TRUE(f.store.is_unlocked());
    EXPECT_GT(f.activity, 0);
}

TEST_F(BrowserRequests, MatchesOnlyTheSite) {
    const json r = send(*s, {{"type", "matches"}, {"url", "https://bank.example.com/signin?x=1"}});
    ASSERT_EQ(r.at("ok"), true) << r.dump();
    EXPECT_EQ(r.at("site").at("domain"), "example.com");
    ASSERT_EQ(r.at("entries").size(), 1u);
    EXPECT_EQ(r.at("entries")[0].at("id"), bank);
    EXPECT_EQ(r.at("entries")[0].at("match"), "domain");
    EXPECT_FALSE(r.at("entries")[0].contains("password")) << "no secrets in lists";

    EXPECT_TRUE(send(*s, {{"type", "matches"}, {"url", "https://bank.example.com.evil.io/"}}).at("entries").empty());
    EXPECT_TRUE(send(*s, {{"type", "matches"}, {"url", "http://www.bank.example.com/"}}).at("entries").empty())
        << "no downgrade to http";
    EXPECT_EQ(send(*s, {{"type", "matches"}, {"url", "file:///etc/passwd"}}).at("code"), "unsupported_page");
}

TEST_F(BrowserRequests, CredentialsForTheMatchingSiteOnly) {
    const json r = send(*s, {{"type", "credentials"}, {"entryId", bank}, {"url", "https://www.bank.example.com/login"}});
    ASSERT_EQ(r.at("ok"), true);
    EXPECT_EQ(r.at("username"), "alice");
    EXPECT_EQ(r.at("password"), "bank-secret");
    EXPECT_EQ(r.at("match"), "exact");

    const json phish = send(*s, {{"type", "credentials"}, {"entryId", bank}, {"url", "https://bank-example.com/login"}});
    EXPECT_EQ(phish.at("code"), "site_mismatch");
    EXPECT_EQ(phish.at("site"), "www.bank.example.com");
    EXPECT_FALSE(phish.contains("password"));

    const json confirmed = send(*s, {{"type", "credentials"},
                                     {"entryId", bank},
                                     {"url", "https://bank-example.com/login"},
                                     {"allowMismatch", true}});
    EXPECT_EQ(confirmed.at("password"), "bank-secret") << "the user confirmed the warning";
    EXPECT_EQ(confirmed.at("match"), "none");

    EXPECT_EQ(send(*s, {{"type", "credentials"}, {"entryId", "nope"}, {"url", "https://x.com"}}).at("code"),
              "entry_not_found");
}

TEST_F(BrowserRequests, Search) {
    const json r = send(*s, {{"type", "search"}, {"query", "BANK"}, {"url", "https://bank.example.net/"}});
    ASSERT_EQ(r.at("ok"), true);
    ASSERT_EQ(r.at("entries").size(), 2u);
    EXPECT_EQ(r.at("entries")[0].at("title"), "Bank");
    EXPECT_EQ(r.at("entries")[0].at("match"), "none");
    EXPECT_EQ(r.at("entries")[0].at("site"), "www.bank.example.com");
    EXPECT_EQ(r.at("entries")[1].at("match"), "exact");
    EXPECT_EQ(send(*s, {{"type", "search"}, {"query", std::string(201, 'a')}}).at("code"), "bad_request");
}

TEST_F(BrowserRequests, GenerateAndCopy) {
    const json r = send(*s, {{"type", "generate"}, {"options", {{"length", 24}}}, {"copy", true}});
    ASSERT_EQ(r.at("ok"), true) << r.dump();
    EXPECT_EQ(std::string(r.at("password")).size(), 24u);
    EXPECT_EQ(r.at("copied"), true);
    ASSERT_EQ(f.clipboard.size(), 1u);
    EXPECT_EQ(f.clipboard[0], r.at("password").get<std::string>());

    const json words = send(*s, {{"type", "generate"}, {"options", {{"kind", "passphrase"}, {"words", 5}}}});
    ASSERT_EQ(words.at("ok"), true);
    EXPECT_GT(words.at("bits"), 60.0);
    EXPECT_EQ(send(*s, {{"type", "generate"}, {"options", {{"kind", "shell"}}}}).at("code"), "bad_request");
}
