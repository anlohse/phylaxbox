/*
 * appui.cpp
 *
 *  Created on: 15 de fev. de 2025
 *      Author: alanl
 */
#include "appui.h"

#include "app_page.h"
#include "async_bind.h"
#include "storage/device_id.h"

#include <sodium.h>

#include <memory>

#ifndef PB_WEBVIEW_DEVTOOLS
#define PB_WEBVIEW_DEVTOOLS 0 // developer tools only in Debug builds
#endif

app_ui::app_ui()
    : w(PB_WEBVIEW_DEVTOOLS != 0, nullptr),
      m_bridge(m_store, pb::load_or_create_device_id(pb::default_device_id_path()), make_hooks()) {
	w.set_title("PhylaxBox - Gerenciador de Senhas");
	w.set_size(1000, 680, WEBVIEW_HINT_NONE);

	// Exposed to the page as window.<name>(...) -> Promise<{ok, code, message, ...}>.
	// Bound before the page loads so the functions exist when its script runs.
	expose("vault_status", &pb::app::vault_bridge::status);
	expose("vault_create", &pb::app::vault_bridge::create);
	expose("vault_unlock", &pb::app::vault_bridge::unlock);
	expose("vault_recover", &pb::app::vault_bridge::recover);
	expose("vault_lock", &pb::app::vault_bridge::lock);
	expose("vault_list", &pb::app::vault_bridge::list);
	expose("vault_get", &pb::app::vault_bridge::get);
	expose("vault_reveal", &pb::app::vault_bridge::reveal);
	expose("vault_add", &pb::app::vault_bridge::add);
	expose("vault_update", &pb::app::vault_bridge::update);
	expose("vault_delete", &pb::app::vault_bridge::remove);
	expose("vault_favorite", &pb::app::vault_bridge::favorite);
	expose("vault_copy", &pb::app::vault_bridge::copy);
	expose("password_generate", &pb::app::vault_bridge::generate);

	w.set_html(std::string(reinterpret_cast<const char*>(pb::app::APP_PAGE_HTML),
	                       sizeof(pb::app::APP_PAGE_HTML)));
}

pb::app::vault_bridge::hooks app_ui::make_hooks() {
	pb::app::vault_bridge::hooks h;
	// Runs on the worker thread: hand the secret to the UI thread (where the
	// clipboard lives) and schedule the clearing.
	h.copy_to_clipboard = [this](pb::secure_string&& text) {
		if (m_closing) return false;
		auto secret = std::make_shared<pb::secure_string>(std::move(text));
		w.dispatch([this, secret] { m_clipboard.copy(pb::view(*secret)); });
		m_clipboard_timer.schedule(pb::app::vault_bridge::CLIPBOARD_CLEAR_AFTER, [this] {
			if (!m_closing) w.dispatch([this] { m_clipboard.clear_if_ours(); });
		});
		return true;
	};
	h.on_lock = [this] {
		m_clipboard_timer.cancel();
		if (!m_closing) w.dispatch([this] { m_clipboard.clear_if_ours(); });
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
