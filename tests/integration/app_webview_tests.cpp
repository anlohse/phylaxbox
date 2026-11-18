// End-to-end check of the desktop UI inside the real webview (WebView2 on
// Windows, WebKitGTK on Linux): the page drives the vault through the bridge
// exactly like a user would — create a vault, confirm the recovery key, lock,
// fail with a wrong password, then unlock.
//
// Needs a desktop session, so it is disabled by default. Run with:
//   phylaxbox_desktop_tests --gtest_also_run_disabled_tests --gtest_filter=*RealWebview*

// GoogleTest and JSON first: on Linux <webview/webview.h> pulls in X11, whose
// macros (None, Bool, Status...) break gtest's headers if they come later.
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "app_page.h"
#include "storage/vault_store.h"
#include "test_helpers.h"
#include "vault_bridge.h"

#include "async_bind.h" // includes <webview/webview.h>
#include "serial_worker.h"

#include <atomic>
#include <string>
#include <vector>

TEST(AppPageWebview, DISABLED_RealWebviewCreateLockUnlock) {
    pb_test::temp_dir dir;
    pb::vault_store store(dir.path() / "vault.phylaxbox", pb_test::fast_kdf());
    pb::app::vault_bridge bridge(store);

    webview::webview w(false, nullptr);
    std::atomic<bool> closing{false};
    pb::app::serial_worker worker;
    std::vector<std::string> steps;
    // Same asynchronous binding as the app (worker thread + resolve).
    using method = std::string (pb::app::vault_bridge::*)(const std::string&);
    for (const auto& [name, m] : std::vector<std::pair<std::string, method>>{
             {"vault_status", &pb::app::vault_bridge::status},
             {"vault_create", &pb::app::vault_bridge::create},
             {"vault_unlock", &pb::app::vault_bridge::unlock},
             {"vault_lock", &pb::app::vault_bridge::lock}}) {
        pb::app::bind_async(w, worker, closing, name,
                            [&bridge, m = m](const std::string& req) { return (bridge.*m)(req); });
    }
    w.bind("__step", [&](const std::string& req) {
        steps.push_back(nlohmann::json::parse(req).at(0).get<std::string>());
        return std::string();
    });
    w.bind("__done", [&](const std::string&) {
        w.terminate();
        return std::string();
    });

    // Test driver, injected before the page script. Waits for each view,
    // acts on it, and records "<view>|<status class>|<status text>".
    w.init(R"js(
      window.addEventListener('DOMContentLoaded', async () => {
        const $ = (id) => document.getElementById(id);
        const visible = (v) => !$('view-' + v).hidden;
        const until = (pred) => new Promise((resolve, reject) => {
          const t0 = Date.now();
          const timer = setInterval(() => {
            if (pred()) { clearInterval(timer); resolve(); }
            else if (Date.now() - t0 > 10000) { clearInterval(timer); reject(new Error('timeout')); }
          }, 25);
        });
        const step = (v) => window.__step(v + '|' + $('status').className + '|' + $('status').textContent);
        const submit = (form) => $(form).requestSubmit();
        try {
          await until(() => visible('create'));                       step('create');
          $('create-password').value = 'short';
          $('create-confirm').value = 'short';
          submit('create-form');                                      step('create');
          $('create-password').value = 'pässword long enough';
          $('create-confirm').value = 'pässword long enough';    // same after NFC
          submit('create-form');
          await until(() => visible('recovery-key'));
          step('recovery-key:' + $('recovery-key-text').textContent.length + ':' + $('recovery-done').disabled);
          $('recovery-saved').click();
          $('recovery-done').click();
          await until(() => visible('unlocked'));                     step('unlocked:' + $('unlocked-summary').textContent);
          $('lock').click();
          await until(() => visible('unlock'));                       step('unlock');
          $('unlock-password').value = 'wrong password';
          submit('unlock-form');
          await until(() => $('status').className === 'error');       step('unlock');
          $('unlock-password').value = 'pässword long enough';
          submit('unlock-form');
          await until(() => visible('unlocked'));                     step('unlocked');
        } catch (e) {
          window.__step('error|' + e.message);
        }
        window.__done();
      });
    )js");
    w.set_html(std::string(reinterpret_cast<const char*>(pb::app::APP_PAGE_HTML),
                           sizeof(pb::app::APP_PAGE_HTML)));
    w.run();
    closing = true;
    worker.stop();

    const std::vector<std::string> expected = {
        "create||",
        "create|error|A senha mestra precisa ter pelo menos 8 caracteres.",
        "recovery-key:65:true|ok|Cofre criado.",
        "unlocked:0 itens no cofre.||",
        "unlock|ok|Cofre bloqueado.",
        "unlock|error|Senha mestra incorreta.",
        "unlocked||",
    };
    EXPECT_EQ(steps, expected);
    EXPECT_TRUE(store.exists());
}
