// End-to-end check of the login page inside the real webview (WebView2 on
// Windows, WebKitGTK on Linux): the page calls window.login, the C++ bridge
// answers, and the page shows the answer.
//
// Needs a desktop session, so it is disabled by default. Run with:
//   phylaxbox_desktop_tests --gtest_also_run_disabled_tests --gtest_filter=*RealWebview*
#include "login_bridge.h"
#include "login_page.h"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <webview/webview.h>

#include <string>

TEST(LoginPageWebview, DISABLED_RealWebviewRoundTrip) {
    webview::webview w(false, nullptr);
    std::string received_password;
    std::string page_status;

    w.bind("login", [&](const std::string& request) {
        return pb::app::handle_login_request(request, [&](std::string_view password) {
            received_password = std::string(password);
            return pb::app::login_result{false, "not_available", "indispon\xC3\xADvel"};
        });
    });
    w.bind("__report", [&](const std::string& request) {
        page_status = nlohmann::json::parse(request).at(0).get<std::string>();
        w.terminate();
        return std::string();
    });
    // Runs before the page's own script: fill in a decomposed "ä" (a + U+0308),
    // submit like the user would, and report the status once the bridge answers.
    w.init(R"js(
        window.addEventListener('DOMContentLoaded', () => {
          document.getElementById('password').value = 'päss';
          document.getElementById('login-form').requestSubmit();
          const timer = setInterval(() => {
            const s = document.getElementById('status');
            if (s.className) {
              clearInterval(timer);
              window.__report(s.className + '|' + s.textContent + '|' +
                              document.getElementById('password').value);
            }
          }, 50);
        });
    )js");
    w.set_html(pb::app::LOGIN_PAGE_HTML);
    w.run();

    EXPECT_EQ(received_password, "p\xC3\xA4ss"); // NFC-normalized UTF-8
    EXPECT_EQ(page_status, "error|indispon\xC3\xADvel|"); // message shown, field cleared
}
