/*
 * appui.cpp
 *
 *  Created on: 15 de fev. de 2025
 *      Author: alanl
 */
#include "appui.h"

#include "app_page.h"
#include "async_bind.h"

#ifndef PB_WEBVIEW_DEVTOOLS
#define PB_WEBVIEW_DEVTOOLS 0 // developer tools only in Debug builds
#endif

app_ui::app_ui() : w(PB_WEBVIEW_DEVTOOLS != 0, nullptr), m_bridge(m_store) {
	w.set_title("PhylaxBox - Gerenciador de Senhas");
	w.set_size(800, 600, WEBVIEW_HINT_NONE);

	// Exposed to the page as window.<name>(...) -> Promise<{ok, code, message, ...}>.
	// Bound before the page loads so the functions exist when its script runs.
	expose("vault_status", &pb::app::vault_bridge::status);
	expose("vault_create", &pb::app::vault_bridge::create);
	expose("vault_unlock", &pb::app::vault_bridge::unlock);
	expose("vault_recover", &pb::app::vault_bridge::recover);
	expose("vault_lock", &pb::app::vault_bridge::lock);

	w.set_html(std::string(reinterpret_cast<const char*>(pb::app::APP_PAGE_HTML),
	                       sizeof(pb::app::APP_PAGE_HTML)));
}

void app_ui::expose(const std::string& name, bridge_method method) {
	pb::app::bind_async(w, m_worker, m_closing, name,
	                    [this, method](const std::string& request) { return (m_bridge.*method)(request); });
}

app_ui::~app_ui() {
	m_closing = true;
	m_worker.stop();
	m_store.lock();
}

void app_ui::show() {
	w.run();
	m_closing = true;
	m_worker.stop();
}
