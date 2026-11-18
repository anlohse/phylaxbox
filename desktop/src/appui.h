/*
 * appui.h
 *
 *  Created on: 15 de fev. de 2025
 *      Author: alanl
 */

#ifndef APPUI_H_
#define APPUI_H_

#include "delayed_action.h"
#include "secret_clipboard.h"
#include "serial_worker.h"
#include "storage/vault_store.h"
#include "vault_bridge.h"

#include <webview/webview.h>

#include <atomic>
#include <string>

class app_ui {
private:
	webview::webview w;
	pb::app::secret_clipboard m_clipboard; // UI thread only
	pb::vault_store m_store;
	pb::app::vault_bridge m_bridge;
	std::atomic<bool> m_closing{false};
	pb::app::delayed_action m_clipboard_timer;
	pb::app::serial_worker m_worker; // destroyed first: joins before the rest goes away

	using bridge_method = std::string (pb::app::vault_bridge::*)(const std::string&);
	void expose(const std::string& name, bridge_method method);
	pb::app::vault_bridge::hooks make_hooks();

public:
	app_ui();
	virtual ~app_ui();
	void show();
};

#endif /* APPUI_H_ */
