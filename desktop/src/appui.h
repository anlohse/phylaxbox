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
#include "session_watcher.h"
#include "storage/vault_store.h"
#include "vault_bridge.h"

#include <webview/webview.h>

#include <atomic>
#include <memory>
#include <string>

class app_ui {
private:
	webview::webview w;
	pb::app::secret_clipboard m_clipboard; // UI thread only
	pb::vault_store m_store;
	pb::app::vault_bridge m_bridge;
	std::atomic<bool> m_closing{false};
	pb::app::delayed_action m_clipboard_timer;
	std::unique_ptr<pb::app::session_watcher> m_session_watcher; // UI thread
	pb::app::serial_worker m_worker; // destroyed first: joins before the rest goes away

	using bridge_method = std::string (pb::app::vault_bridge::*)(const std::string&);
	void expose(const std::string& name, bridge_method method);
	pb::app::vault_bridge::hooks make_hooks();
	void on_lock_event(pb::app::vault_bridge::lock_event event); // UI thread

public:
	app_ui();
	virtual ~app_ui();
	void show();
};

#endif /* APPUI_H_ */
