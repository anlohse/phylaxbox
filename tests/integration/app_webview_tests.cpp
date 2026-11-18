// End-to-end check of the desktop UI inside the real webview (WebView2 on
// Windows, WebKitGTK on Linux): the page drives the vault through the bridge
// exactly like a user would. The clipboard is replaced by a recording hook so
// the test never touches the real one.
//
// Needs a desktop session, so it is disabled by default. Run with:
//   phylaxbox_desktop_tests --gtest_also_run_disabled_tests --gtest_filter=*RealWebview*

// GoogleTest and JSON first: on Linux <webview/webview.h> pulls in X11, whose
// macros (None, Bool, Status...) break gtest's headers if they come later.
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "app_page.h"
#include "storage/device_settings.h"
#include "storage/vault_store.h"
#include "test_helpers.h"
#include "vault_bridge.h"

#include "async_bind.h" // includes <webview/webview.h>
#include "serial_worker.h"

#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <vector>

namespace {

const std::string kDevice = "0b6e1c1a-3f5d-4a8e-9c2b-7d4e5f6a7b8c";

// Test driver, injected before the page script. Each step waits for the UI
// to reach a state, acts like a user, and records what it saw.
const char* DRIVER = R"js(
  window.__violations = [];
  document.addEventListener('securitypolicyviolation', (e) => window.__violations.push(e.violatedDirective));
  window.addEventListener('DOMContentLoaded', async () => {
    const $ = (id) => document.getElementById(id);
    window.confirm = () => true; // no modal dialogs in the test
    const visible = (id) => !$(id).hidden;
    const until = (what, pred) => new Promise((resolve, reject) => {
      const t0 = Date.now();
      const timer = setInterval(() => {
        if (pred()) { clearInterval(timer); resolve(); }
        else if (Date.now() - t0 > 10000) { clearInterval(timer); reject(new Error('timeout: ' + what)); }
      }, 25);
    });
    const step = (s) => window.__step(s);
    const status = () => $('status').className + '|' + $('status').textContent;
    const vaultStatus = () => $('vault-status').className + '|' + $('vault-status').textContent;
    const titles = () => [...$('entry-list').children].map((li) => li.querySelector('.title').textContent).join(',');
    const type = (id, value) => { $(id).value = value; $(id).dispatchEvent(new Event('input', { bubbles: true })); };
    try {
      // --- create the vault ---
      await until('create view', () => visible('view-create'));
      type('create-password', 'pässword long enough');
      type('create-confirm', 'pässword long enough');
      $('create-form').requestSubmit();
      await until('recovery key', () => visible('view-recovery-key'));
      step('recovery-key:' + $('recovery-key-text').textContent.length);
      $('recovery-saved').click();
      $('recovery-done').click();
      await until('vault', () => visible('vault'));
      step('empty:' + $('detail-empty-text').textContent);

      // --- add an entry with a generated password ---
      $('new-entry').click();
      await until('editor', () => visible('edit-form'));
      type('f-title', 'Banco');
      type('f-username', 'alice');
      $('f-generate').click();
      await until('generated', () => $('f-password').value.length === 20);
      type('f-urls', 'https://banco.example\n\nhttps://app.banco.example');
      $('edit-form').requestSubmit();
      await until('saved', () => visible('detail-view') && titles() === 'Banco');
      step('saved:' + $('d-title').textContent + '|' + $('d-username').textContent + '|' + $('d-password').textContent + '|' + vaultStatus());

      // --- reveal, hide, copy ---
      $('toggle-password').click();
      await until('revealed', () => $('d-password').textContent.length === 20);
      step('revealed');
      $('toggle-password').click();
      step('hidden:' + $('d-password').textContent);
      $('copy-password').click();
      await until('copied', () => $('vault-status').textContent.startsWith('Senha copiada'));
      step('copied:' + vaultStatus());

      // --- second entry, search and tag filter ---
      $('new-entry').click();
      await until('editor 2', () => visible('edit-form') && $('f-title').value === '');
      type('f-title', 'Email');
      type('f-password', 'secret');
      type('f-tags', 'pessoal, pessoal , ');
      $('f-favorite').checked = true;
      $('edit-form').requestSubmit();
      await until('saved 2', () => titles() === 'Email,Banco'); // favorites first
      step('list:' + titles() + '|tags:' + [...$('tag-filter').options].map((o) => o.value).join(','));
      type('search', 'BAN');
      step('search:' + titles());
      type('search', '');
      $('tag-filter').value = 'pessoal';
      $('tag-filter').dispatchEvent(new Event('change'));
      step('tag:' + titles());
      $('tag-filter').value = '';
      $('tag-filter').dispatchEvent(new Event('change'));

      // --- delete ---
      [...$('entry-list').children].find((li) => li.querySelector('.title').textContent === 'Banco').click();
      await until('select Banco', () => $('d-title').textContent === 'Banco');
      $('delete-entry').click();
      $('delete-yes').click();
      await until('deleted', () => titles() === 'Email' && visible('detail-empty'));
      step('deleted:' + vaultStatus());

      // --- passphrase generator (cancelled edit) ---
      $('new-entry').click();
      await until('editor 3', () => visible('edit-form') && $('f-title').value === '');
      $('g-mode').value = 'passphrase';
      $('g-mode').dispatchEvent(new Event('change'));
      $('f-generate').click();
      await until('passphrase', () => $('f-password').value.split('-').length === 6);
      step('passphrase:' + visible('g-passphrase-options') + '|' + $('g-strength').textContent);
      $('cancel-edit').click();
      await until('cancelled', () => visible('detail-empty'));

      // --- settings: preferences, master password, language ---
      $('open-settings').click();
      await until('settings', () => visible('settings') && $('about-version').textContent !== '');
      step('settings:' + $('s-autolock').value + '|' + $('s-clipboard').value + '|' + $('rk-state').textContent + '|' + ($('backup-rows').children.length > 0));
      $('s-clipboard').value = '45';
      $('s-save-security').click();
      await until('prefs saved', () => vaultStatus() === 'ok|Configurações salvas.');
      type('cp-current', 'pässword long enough');
      type('cp-new', 'a brand new master password');
      type('cp-confirm', 'a brand new master password');
      $('change-password-form').requestSubmit();
      await until('password changed', () => vaultStatus() === 'ok|Senha mestra trocada.');
      step('password:' + vaultStatus() + '|' + $('cp-current').value + $('cp-new').value);
      $('s-language').value = 'en';
      $('s-language').dispatchEvent(new Event('change'));
      await until('english', () => $('lock').textContent === 'Lock' && $('rk-state').textContent.startsWith('This'));
      step('en:' + document.documentElement.lang + '|' + $('settings').querySelector('h2').textContent + '|' + $('rk-state').textContent);
      $('close-settings').click();
      $('entry-list').children[0].click();
      await until('select Email', () => $('d-title').textContent === 'Email');
      $('copy-password').click();
      await until('copied en', () => $('vault-status').textContent.startsWith('Password copied'));
      step('copied:' + vaultStatus());

      // --- lock and unlock ---
      $('lock').click();
      await until('locked', () => visible('view-unlock'));
      step('locked:' + status());
      type('unlock-password', 'pässword long enough');
      $('unlock-form').requestSubmit();
      await until('wrong', () => status().startsWith('error'));
      step('wrong:' + status());
      type('unlock-password', 'a brand new master password');
      $('unlock-form').requestSubmit();
      await until('unlocked', () => visible('vault') && titles() === 'Email');
      step('unlocked:' + titles());
      step('csp:' + window.__violations.join(','));
      // The policy is in force: eval is refused (no 'unsafe-eval').
      let evalBlocked = false;
      try { new Function('return 1')(); } catch (e) { evalBlocked = true; }
      step('eval-blocked:' + evalBlocked);
    } catch (e) {
      step('error|' + e.message + '|' + vaultStatus() + '|' + status());
    }
    window.__done();
  });
)js";

} // namespace

TEST(AppPageWebview, DISABLED_RealWebviewEndToEnd) {
    pb_test::temp_dir dir;
    pb::vault_store store(dir.path() / "vault.phylaxbox", pb_test::fast_kdf());
    std::mutex clipboard_mutex;
    std::vector<std::string> clipboard;
    pb::app::vault_bridge::hooks hooks;
    std::vector<std::chrono::seconds> clear_after;
    hooks.copy_to_clipboard = [&](pb::secure_string&& text, std::chrono::seconds after) {
        std::lock_guard<std::mutex> lock(clipboard_mutex);
        clipboard.emplace_back(text.data(), text.size());
        clear_after.push_back(after);
        return true;
    };
    // Fixed language, so the texts checked below do not depend on the machine.
    pb::device_settings settings;
    settings.language = "pt-BR";
    settings.save(dir.path() / "settings.json");
    pb::app::vault_bridge bridge(store, kDevice, dir.path() / "settings.json", hooks);

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
             {"vault_lock", &pb::app::vault_bridge::lock},
             {"vault_list", &pb::app::vault_bridge::list},
             {"vault_get", &pb::app::vault_bridge::get},
             {"vault_reveal", &pb::app::vault_bridge::reveal},
             {"vault_add", &pb::app::vault_bridge::add},
             {"vault_update", &pb::app::vault_bridge::update},
             {"vault_delete", &pb::app::vault_bridge::remove},
             {"vault_favorite", &pb::app::vault_bridge::favorite},
             {"vault_copy", &pb::app::vault_bridge::copy},
             {"settings_get", &pb::app::vault_bridge::settings_get},
             {"settings_set_device", &pb::app::vault_bridge::settings_set_device},
             {"settings_set_vault", &pb::app::vault_bridge::settings_set_vault},
             {"password_change", &pb::app::vault_bridge::change_password},
             {"recovery_regenerate", &pb::app::vault_bridge::regenerate_recovery_key},
             {"recovery_remove", &pb::app::vault_bridge::remove_recovery_key},
             {"backups_list", &pb::app::vault_bridge::backups_list},
             {"backup_restore", &pb::app::vault_bridge::backup_restore},
             {"vault_unlock_backup", &pb::app::vault_bridge::unlock_from_backup},
             {"passphrase_generate", &pb::app::vault_bridge::generate_passphrase},
             {"app_info", &pb::app::vault_bridge::app_info},
             {"password_generate", &pb::app::vault_bridge::generate}}) {
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
    w.init(DRIVER);
    w.set_html(std::string(reinterpret_cast<const char*>(pb::app::APP_PAGE_HTML),
                           sizeof(pb::app::APP_PAGE_HTML)));
    w.run();
    closing = true;
    worker.stop();

    const std::vector<std::string> expected = {
        "recovery-key:65",
        "empty:O cofre está vazio. Use \"+ Novo item\" para adicionar uma senha.",
        "saved:Banco|alice|••••••••|ok|Item salvo.",
        "revealed",
        "hidden:••••••••",
        "copied:ok|Senha copiada. A área de transferência será limpa em 30 s.",
        "list:Email,Banco|tags:,pessoal",
        "search:Banco",
        "tag:Email",
        "deleted:ok|Item excluído.",
        "passphrase:true|Força estimada: 77 bits.",
        "settings:5|30|Este cofre tem uma chave de recuperação.|true",
        "password:ok|Senha mestra trocada.|",
        "en:en|Settings|This vault has a recovery key.",
        "copied:ok|Password copied. The clipboard will be cleared in 45 s.",
        "locked:ok|Vault locked.",
        "wrong:error|Wrong master password.",
        "unlocked:Email",
        "csp:",
        "eval-blocked:true",
    };
    EXPECT_EQ(steps, expected);

    // What reached the clipboard: the generated password of "Banco", then the
    // password of "Email", cleared after the configured time.
    ASSERT_EQ(clipboard.size(), 2u);
    EXPECT_EQ(clipboard[0].size(), 20u);
    EXPECT_EQ(clipboard[1], "secret");
    EXPECT_EQ(clear_after, (std::vector<std::chrono::seconds>{std::chrono::seconds(30), std::chrono::seconds(45)}));
    // The vault on disk has the remaining entry, with URLs cleaned up.
    pb::vault_store reopened(store.path(), pb_test::fast_kdf());
    reopened.unlock("a brand new master password");
    ASSERT_EQ(reopened.document().entries.size(), 1u);
    EXPECT_EQ(reopened.document().entries[0].title, "Email");
    ASSERT_EQ(reopened.document().entries[0].tags.size(), 1u); // duplicates and blanks dropped
    EXPECT_EQ(reopened.document().tombstones.size(), 1u);
}
