/*
 * appui.h
 *
 *  Created on: 15 de fev. de 2025
 *      Author: alanl
 */

#ifndef APPUI_H_
#define APPUI_H_

#include <webview/webview.h>

class app_ui {
private:
	webview::webview w;
public:
	app_ui();
	virtual ~app_ui();
	void show();
};

#endif /* APPUI_H_ */
