/*
 * configservice.h
 *
 *  Created on: 17 de fev. de 2025
 *      Author: alanl
 */

#ifndef CONFIGSERVICE_H_
#define CONFIGSERVICE_H_

#include "pb_types.h"
#include <vector>
#include <filesystem>

class config_service {
private:
	PBConfiguration m_config;
	std::filesystem::file_time_type last_update_time;
	std::string last_checksum;
public:
	config_service();
	virtual ~config_service();



	void load_config(const std::vector<unsigned char>& key);

	void save_config(const std::vector<unsigned char>& key);

	const PBConfiguration& get_config() const;

	config_service& set_config(const PBConfiguration& n_config);

};

#endif /* CONFIGSERVICE_H_ */
