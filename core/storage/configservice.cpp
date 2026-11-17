/*
 * configservice.cpp
 *
 *  Created on: 17 de fev. de 2025
 *      Author: alanl
 */

#include "storage/configservice.h"

#include "storage/file_io.h"
#include "models/pbexceptions.h"

#include <nlohmann/json.hpp>

#include <utility>

namespace {

constexpr int CONFIG_FORMAT = 1;

const char* engine_name(sync_engine_t e) {
	switch (e) {
	case DROPBOX: return "dropbox";
	case G_DRIVE: return "gdrive";
	case NO_SYNC: break;
	}
	return "none";
}

sync_engine_t engine_from_name(const std::string& s) {
	if (s == "dropbox") return DROPBOX;
	if (s == "gdrive") return G_DRIVE;
	if (s == "none") return NO_SYNC;
	throw vault_format_exception("unknown sync engine in config: " + s);
}

PBConfiguration parse_config(std::string_view text) {
	try {
		const auto js = nlohmann::json::parse(text);
		if (js.at("format").get<int>() != CONFIG_FORMAT) {
			throw vault_format_exception("unsupported config format",
			                             ErrorCodes::UNSUPPORTED_VERSION);
		}
		PBConfiguration cfg;
		cfg.sync_engine = engine_from_name(js.at("sync_engine").get<std::string>());
		cfg.sync_token = js.value("sync_token", std::string());
		return cfg;
	} catch (const nlohmann::json::exception& e) {
		throw vault_format_exception(std::string("invalid config content: ") + e.what());
	}
}

} // namespace

config_service::config_service(std::filesystem::path file, pb::crypto::kdf_params kdf)
	: m_path(std::move(file)), m_kdf(kdf) {
}

std::filesystem::path config_service::default_path() {
	return pb::file_io::default_data_dir() / "config.pbx";
}

bool config_service::exists() const {
	std::error_code ec;
	return std::filesystem::is_regular_file(m_path, ec);
}

void config_service::create(std::string_view password, const PBConfiguration& initial) {
	m_container = pb::vault_container::create(password, pb::content_type::local_config, m_kdf);
	m_config = initial;
	try {
		save();
	} catch (...) {
		lock();
		throw;
	}
}

void config_service::load(std::string_view password) {
	const auto file = pb::file_io::read_file(m_path);
	pb::secure_bytes content;
	auto container =
		pb::vault_container::open(password, file, pb::content_type::local_config, content);
	m_config = parse_config(content.as_string_view());
	m_container = std::move(container);
}

void config_service::save() {
	if (!m_container) {
		throw pbexception(ErrorCodes::VAULT_LOCKED, "config is locked");
	}
	nlohmann::json js;
	js["format"] = CONFIG_FORMAT;
	js["sync_engine"] = engine_name(m_config.sync_engine);
	js["sync_token"] = m_config.sync_token;
	const std::string text = js.dump();

	const auto file = m_container->seal(std::string_view(text));
	pb::file_io::write_file_atomic(m_path, file);
}

void config_service::lock() {
	m_container.reset();
	m_config = PBConfiguration();
}

const PBConfiguration& config_service::get_config() const {
	return m_config;
}

config_service& config_service::set_config(const PBConfiguration& n_config) {
	m_config = n_config;
	return *this;
}
