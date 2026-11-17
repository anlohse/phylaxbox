/*
 * syncclients.cpp
 *
 *  Created on: 16 de fev. de 2025
 *      Author: alanl
 */

#include "syncclients.h"

#ifndef CPPHTTPLIB_OPENSSL_SUPPORT
#define CPPHTTPLIB_OPENSSL_SUPPORT
#endif

#include <httplib.h>
#include <iostream>
#include <fstream>
#include <algorithm>
#include "pbexceptions.h"

class dropbox_auth_server {
private:
	httplib::Server svr;
	std::string token;
public:
	dropbox_auth_server(): svr() {
		svr.Get("/phylaxbox/callback", [&](const httplib::Request &req, httplib::Response &res) {
			auto it = req.params.find("code");
			if (it != req.params.end()) {
				dropbox_auth_server::token = it->second;
				res.set_content("success", "text/plain");
			} else {
				res.status = 400;
				res.set_content("error: code not present", "text/plain");
			}
		});
	}
	virtual ~dropbox_auth_server() {
		stop();
	}

	virtual void listen(int port) {
		svr.listen("0.0.0.0", port);
	}

	virtual void stop() {
		if (svr.is_running()) {
			svr.stop();
		}
	}
};


class dropbox_sync_client : public __interfaces::_sync_client  {
private:
	std::string token;
	dropbox_auth_server auth_server;
public:
	dropbox_sync_client() {

	}
	virtual ~dropbox_sync_client() {

	}

	virtual void init(const PBConfiguration& config) {
		token = config.sync_token;
	}

	virtual bool load(const std::string& dest_file) {
	    httplib::Client cli("https://content.dropboxapi.com");
	    httplib::Headers headers = {
	        {"Authorization", "Bearer " + token},
	        {"Dropbox-API-Arg", R"({"path": "/PhylaxBox/vault.dat"})"}
	    };

	    auto res = cli.Post("/2/files/download", headers);

	    if (res && res->status / 100 == 2) {
	        std::ofstream file(dest_file, std::ios::binary);
	        if (!file) {
	            throw ioexception(ErrorCodes::CANT_CREATE_FILE, dest_file);
	        }

	        file.write(res->body.c_str(), res->body.size());
	        file.close();
	        std::cout << "Download concluído e salvo em " << dest_file << "\n";
	        return true;
	    } else {
			throwHttpException(res->status);
	    }
	}

	virtual bool send(const std::string& source_file) {
	    std::ifstream file(source_file, std::ios::binary);
	    if (!file) {
	        throw ioexception(ErrorCodes::FILE_NOT_FOUND, source_file);
	    }

	    // Ler todo o conteúdo do arquivo
	    std::string fileData((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

	    httplib::Client cli("https://content.dropboxapi.com");
	    httplib::Headers headers = {
	        {"Authorization", "Bearer " + token},
	        {"Content-Type", "application/octet-stream"},
	        {"Dropbox-API-Arg", R"({"path": "/PhylaxBox/vault.dat", "mode": "overwrite"})"}
	    };

	    auto res = cli.Post("/2/files/upload", headers, fileData, "application/octet-stream");

	    if (res && res->status / 100 == 2) {
	        std::cout << "Arquivo enviado com sucesso!\n";
	        return true;
	    } else {
			throwHttpException(res->status);
	    }
	}

	virtual void remove() {
		httplib::Client cli("https://api.dropboxapi.com");
		httplib::Headers headers = {
			{"Authorization", "Bearer " + token},
			{"Content-Type", "application/json"}
		};
		std::string data = R"({"path": "/PhylaxBox/vault.dat"})";
		auto res = cli.Post("/2/files/delete_v2", headers, data, "application/json");

		if (res && res->status / 100 == 2) {
			std::cout << "Arquivo enviado com sucesso!\n";
		} else {
			throwHttpException(res->status);
		}
	}

	virtual void startLocalserver() {
		auth_server.listen(LOCAL_PORT);
	}

	virtual bool authenticate() {
		return false;
	}

	virtual void stopLocalserver() {
		auth_server.stop();
	}

};


class gdrive_sync_client : public __interfaces::_sync_client  {
public:
	gdrive_sync_client() {

	}
	virtual ~gdrive_sync_client() {

	}

	virtual void init(const PBConfiguration& config) {

	}

	virtual bool load(const std::string& dest_file) {
		return false;
	}

	virtual bool send(const std::string& source_file) {
		return false;
	}

	virtual void remove() {

	}
	virtual void startLocalserver() {

	}

	virtual bool authenticate() {
		return false;
	}

	virtual void stopLocalserver() {

	}

};


sync_client::sync_client(const sync_engine_t& engine_type) {
	switch (engine_type) {
	case DROPOX:
		_client = std::make_unique<dropbox_sync_client>();
		break;
	case G_DRIVE:
		_client = std::make_unique<gdrive_sync_client>();
		break;
	}
}

sync_client sync_client::create_client(const sync_engine_t& engine_type) {
	return sync_client(engine_type);
}

sync_client::sync_client(sync_client&& other) noexcept : _client(std::move(other._client)) {
}

sync_client::~sync_client() {

}

void sync_client::init(const PBConfiguration& config) {
	if (_client)
		_client->init(config);
}

bool sync_client::load(const std::string& dest_file) {
	if (_client)
		return _client->load(dest_file);
}

bool sync_client::send(const std::string& source_file) {
	if (_client)
		return _client->send(source_file);
}

void sync_client::remove() {
	if (_client)
		_client->remove();
}

sync_client& sync_client::operator=(sync_client&& other) {
	_client = std::move(other._client);
	return *this;
}

void sync_client::startLocalserver() {
	if (_client)
		_client->startLocalserver();
}

bool sync_client::authenticate() {
	if (_client)
		return _client->authenticate();
}

void sync_client::stopLocalserver() {
	if (_client)
		_client->stopLocalserver();
}
