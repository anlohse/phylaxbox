/*
 * appui.cpp
 *
 *  Created on: 15 de fev. de 2025
 *      Author: alanl
 */
#include "appui.h"

#include "login_bridge.h"
#include "login_page.h"

#ifndef PB_WEBVIEW_DEVTOOLS
#define PB_WEBVIEW_DEVTOOLS 0 // developer tools only in Debug builds
#endif

namespace {

// Placeholder until the vault session (open/create the local vault) exists.
// It must never report success without actually unlocking a vault.
pb::app::login_result unlock_vault(std::string_view /*password*/) {
	return {false, "not_available",
	        "O desbloqueio do cofre ainda n\xC3\xA3o est\xC3\xA1 dispon\xC3\xADvel nesta vers\xC3\xA3o."};
}

} // namespace

app_ui::app_ui(): w(PB_WEBVIEW_DEVTOOLS != 0, nullptr) {
	w.set_title("PhylaxBox - Gerenciador de Senhas");
	w.set_size(800, 600, WEBVIEW_HINT_NONE);

	// Exposed to the page as window.login(password) -> Promise<{ok, code, message}>.
	// Bind before set_html so the function exists when the page loads.
	w.bind("login", [](const std::string& request) -> std::string {
		return pb::app::handle_login_request(request, unlock_vault);
	});

	w.set_html(pb::app::LOGIN_PAGE_HTML);
}

app_ui::~app_ui() = default;

void app_ui::show() {
	w.run();
}
