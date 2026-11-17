/*
 * appui.cpp
 *
 *  Created on: 15 de fev. de 2025
 *      Author: alanl
 */
#include <string>
#include <iostream>
#include "appui.h"

app_ui::app_ui(): w(true, nullptr) {
	w.set_title("PhylaxBox - Gerenciador de Senhas");
	w.set_size(800, 600, WEBVIEW_HINT_NONE);
	std::string html = R"html(
	        <html>
	        <body>
	            <h1>Bem-vindo ao PhylaxBox</h1>
	            <input type="password" id="senha" placeholder="Digite sua senha mestra">
	            <button onclick="window.external.invoke(document.getElementById('senha').value)">Login</button>
	        </body>
	        </html>
	    )html";

	    // Carregar a interface
	    w.set_html(html);

	    // Callback para comunicação com o JavaScript
	    w.bind("login", [&](const std::string &senha) -> std::string {
	        std::cout << "Senha digitada: " << senha << std::endl;
	        return std::string();
	    });
}

app_ui::~app_ui() {
	// TODO Auto-generated destructor stub
}

void app_ui::show() {
	w.run();
}
