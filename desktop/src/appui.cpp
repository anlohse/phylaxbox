/*
 * appui.cpp
 *
 *  Created on: 15 de fev. de 2025
 *      Author: alanl
 */
#include "appui.h"

#include "app_page.h"
#include "async_bind.h"
#include "file_dialog.h"
#include "storage/device_id.h"
#include "storage/device_settings.h"

#include <chrono>
#include <future>
#include <memory>

#ifndef PB_WEBVIEW_DEVTOOLS
#define PB_WEBVIEW_DEVTOOLS 0 // developer tools only in Debug builds
#endif

app_ui::app_ui()
    : w(PB_WEBVIEW_DEVTOOLS != 0, nullptr),
      m_store(pb::device_settings::load(pb::device_settings::default_path()).effective_vault_path()),
      m_bridge(m_store, pb::load_or_create_device_id(pb::default_device_id_path()),
               pb::device_settings::default_path(), make_hooks()) {
	w.set_title("PhylaxBox");
	w.set_size(1000, 700, WEBVIEW_HINT_NONE);

	// Exposed to the page as window.<name>(...) -> Promise<{ok, code, message, ...}>.
	// Bound before the page loads so the functions exist when its script runs.
	using b = pb::app::vault_bridge;
	expose("vault_status", &b::status);
	expose("vault_create", &b::create);
	expose("vault_unlock", &b::unlock);
	expose("vault_recover", &b::recover);
	expose("vault_lock", &b::lock);
	expose("vault_choose", &b::choose_vault);
	expose("vault_use_default", &b::use_default_vault);
	expose("vault_list", &b::list);
	expose("vault_get", &b::get);
	expose("vault_reveal", &b::reveal);
	expose("vault_add", &b::add);
	expose("vault_update", &b::update);
	expose("vault_delete", &b::remove);
	expose("vault_favorite", &b::favorite);
	expose("vault_copy", &b::copy);
	expose("settings_get", &b::settings_get);
	expose("settings_set_device", &b::settings_set_device);
	expose("settings_set_vault", &b::settings_set_vault);
	expose("password_change", &b::change_password);
	expose("recovery_regenerate", &b::regenerate_recovery_key);
	expose("recovery_remove", &b::remove_recovery_key);
	expose("backups_list", &b::backups_list);
	expose("backup_restore", &b::backup_restore);
	expose("vault_unlock_backup", &b::unlock_from_backup);
	expose("password_generate", &b::generate);
	expose("passphrase_generate", &b::generate_passphrase);
	expose("app_info", &b::app_info);

	w.set_html(std::string(reinterpret_cast<const char*>(pb::app::APP_PAGE_HTML),
	                       sizeof(pb::app::APP_PAGE_HTML)));

	// Lock on OS session lock / minimize, if the vault preferences ask for it.
	if (auto window = w.window(); window.ok()) {
		pb::app::session_watcher::callbacks cb;
		cb.on_session_locked = [this] { on_lock_event(pb::app::vault_bridge::lock_event::session_locked); };
		cb.on_minimized = [this] { on_lock_event(pb::app::vault_bridge::lock_event::minimized); };
		m_session_watcher = std::make_unique<pb::app::session_watcher>(window.value(), std::move(cb));
	}
}

void app_ui::on_lock_event(pb::app::vault_bridge::lock_event event) {
	m_worker.post([this, event] {
		if (!m_bridge.auto_lock(event) || m_closing) return;
		const char* reason = event == pb::app::vault_bridge::lock_event::session_locked ? "session" : "minimize";
		const std::string js = std::string("window.pbOnAutoLock && window.pbOnAutoLock('") + reason + "')";
		w.dispatch([this, js] { w.eval(js); });
	});
}

pb::app::vault_bridge::hooks app_ui::make_hooks() {
	pb::app::vault_bridge::hooks h;
	// Runs on the worker thread: hand the secret to the UI thread (where the
	// clipboard lives) and schedule the clearing.
	h.copy_to_clipboard = [this](pb::secure_string&& text, std::chrono::seconds clear_after) {
		if (m_closing) return false;
		auto secret = std::make_shared<pb::secure_string>(std::move(text));
		w.dispatch([this, secret] { m_clipboard.copy(pb::view(*secret)); });
		m_clipboard_timer.schedule(clear_after, [this] {
			if (!m_closing) w.dispatch([this] { m_clipboard.clear_if_ours(); });
		});
		return true;
	};
	h.on_lock = [this] {
		m_clipboard_timer.cancel();
		if (!m_closing) w.dispatch([this] { m_clipboard.clear_if_ours(); });
	};
	// Runs on the worker thread: the dialog must run on the UI thread, so
	// dispatch it there and wait (giving up if the window is closing).
	h.choose_file = [this](const pb::app::file_dialog_request& request) -> std::optional<std::string> {
		auto result = std::make_shared<std::promise<std::optional<std::string>>>();
		auto future = result->get_future();
		w.dispatch([this, request, result] {
			void* parent = nullptr;
			if (auto window = w.window(); window.ok()) parent = window.value();
			result->set_value(pb::app::choose_vault_file(parent, request));
		});
		while (future.wait_for(std::chrono::milliseconds(100)) != std::future_status::ready) {
			if (m_closing) return std::nullopt;
		}
		return future.get();
	};
	return h;
}

void app_ui::expose(const std::string& name, bridge_method method) {
	pb::app::bind_async(w, m_worker, m_closing, name,
	                    [this, method](const std::string& request) { return (m_bridge.*method)(request); });
}

app_ui::~app_ui() {
	m_closing = true;
	m_worker.stop();
	m_clipboard_timer.cancel();
	m_session_watcher.reset();
	m_store.lock();
}

void app_ui::show() {
	w.run();
	// The window is gone: do not leave a password behind on the clipboard.
	m_closing = true;
	m_worker.stop();
	m_clipboard_timer.cancel();
	m_clipboard.clear_if_ours();
}
