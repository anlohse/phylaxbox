/*
 * configservice.cpp
 *
 *  Created on: 17 de fev. de 2025
 *      Author: alanl
 */

#include "configservice.h"
#include "zlibutils.h"
#include "Crypto.h"
#include <iostream>
#include <fstream>
#include <nlohmann/json.hpp>

config_service::config_service() {
}

config_service::~config_service() {
}

void config_service::load_config(const std::vector<unsigned char>& key) {
	std::size_t size = std::filesystem::file_size("config.dat");
    std::ifstream fs("config.dat", std::ios::binary | std::ios::in);
    if (!fs) {
        std::cerr << "Config file not found. Ignoring. " << std::endl;
        return;
    }

    std::vector<uint8_t> encripted(size);
    fs.read(reinterpret_cast<char*>(encripted.data()), size);
    fs.close();	

	std::vector<uint8_t> data(size);
	Crypto::decryptData(key, encripted, data);

	nlohmann::json js = nlohmann::json::parse(data);

	m_config.sync_engine = js["engine"];
	m_config.sync_token = js["token"];
}

void config_service::save_config(const std::vector<unsigned char>& key) {
	nlohmann::json json_obj;

    json_obj["engine"] = m_config.sync_engine;
    json_obj["token"] = m_config.sync_token;


	auto data = compressData(json_obj.dump());

	std::vector<uint8_t> encripted;

	Crypto::encryptData(key, data, encripted);

	std::ofstream fs("config.dat", std::ios::binary | std::ios::out);
    if (!fs) {
        std::cerr << "Error trying to save the file config.dat" << std::endl;
        return;
    }

    fs.write(reinterpret_cast<const char*>(encripted.data()), encripted.size());

    fs.close();
}

const PBConfiguration& config_service::get_config() const {
	return m_config;
}

config_service& config_service::set_config(const PBConfiguration& n_config) {
	m_config = n_config;
	return *this;
}
