#include "login_bridge.h"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <string>

using pb::app::handle_login_request;
using pb::app::login_result;
using json = nlohmann::json;

namespace {

// Unlock stub that records what it received.
struct recorder {
    int calls = 0;
    std::string last_password;
    login_result answer{true, "", ""};

    pb::app::unlock_fn fn() {
        return [this](std::string_view password) {
            ++calls;
            last_password = std::string(password);
            return answer;
        };
    }
};

json call(const std::string& request, recorder& r) {
    const std::string out = handle_login_request(request, r.fn());
    // The webview splices this into JavaScript and JSON.parse()s it.
    for (unsigned char c : out) EXPECT_LT(c, 0x80) << "reply must be ASCII-only";
    return json::parse(out);
}

} // namespace

TEST(LoginBridge, PassesThePasswordAndReturnsTheResult) {
    recorder r;
    const auto reply = call(R"(["correct horse"])", r);
    EXPECT_EQ(r.calls, 1);
    EXPECT_EQ(r.last_password, "correct horse");
    EXPECT_EQ(reply.at("ok"), true);
}

TEST(LoginBridge, UnicodePasswordArrivesAsUtf8) {
    recorder r;
    call(R"(["pässwörd ✓"])", r);
    EXPECT_EQ(r.last_password, "p\xC3\xA4ssw\xC3\xB6rd \xE2\x9C\x93");
}

TEST(LoginBridge, FailuresAreReportedWithoutThePassword) {
    recorder r;
    r.answer = {false, "wrong_password", "Senha incorreta."};
    const std::string out = handle_login_request(R"(["hunter2-secret"])", r.fn());
    EXPECT_EQ(out.find("hunter2-secret"), std::string::npos);
    const auto reply = json::parse(out);
    EXPECT_EQ(reply.at("ok"), false);
    EXPECT_EQ(reply.at("code"), "wrong_password");
    EXPECT_EQ(reply.at("message"), "Senha incorreta.");
}

TEST(LoginBridge, NonAsciiMessagesAreEscaped) {
    recorder r;
    r.answer = {false, "x", "n\xC3\xA3o"};
    EXPECT_EQ(call(R"(["pw"])", r).at("message"), "n\xC3\xA3o");
}

TEST(LoginBridge, EmptyPasswordDoesNotReachUnlock) {
    recorder r;
    EXPECT_EQ(call(R"([""])", r).at("code"), "empty_password");
    EXPECT_EQ(r.calls, 0);
}

TEST(LoginBridge, MalformedRequestsAreRejected) {
    for (const char* request : {"", "not json", "{}", "[]", R"(["a","b"])", "[1]", "[null]",
                                R"({"password":"x"})"}) {
        recorder r;
        EXPECT_EQ(call(request, r).at("code"), "bad_request") << request;
        EXPECT_EQ(r.calls, 0) << request;
    }
}

TEST(LoginBridge, ExceptionsFromUnlockBecomeInternalErrors) {
    const std::string out = handle_login_request(
        R"(["pw"])", [](std::string_view) -> login_result { throw std::runtime_error("boom"); });
    const auto reply = json::parse(out);
    EXPECT_EQ(reply.at("ok"), false);
    EXPECT_EQ(reply.at("code"), "internal_error");
    EXPECT_EQ(out.find("boom"), std::string::npos); // internal details stay internal
}
