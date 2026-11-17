/*
 * configservice.h
 *
 *  Created on: 17 de fev. de 2025
 *      Author: alanl
 */

#ifndef CONFIGSERVICE_H_
#define CONFIGSERVICE_H_

#include "crypto/crypto.h"
#include "models/pb_types.h"
#include "vault/vault_file.h"

#include <filesystem>
#include <optional>
#include <string_view>

// Device-local configuration (which cloud to sync with, its token...),
// encrypted with the master password in a content_type::local_config container.
class config_service {
private:
	std::filesystem::path m_path;
	pb::crypto::kdf_params m_kdf;
	PBConfiguration m_config;
	std::optional<pb::vault_container> m_container; // set while unlocked

public:
	explicit config_service(std::filesystem::path file = default_path(),
	                        pb::crypto::kdf_params kdf = pb::crypto::kdf_params::recommended());

	// <data dir>/config.pbx (see pb::file_io::default_data_dir()).
	static std::filesystem::path default_path();

	const std::filesystem::path& path() const { return m_path; }
	bool exists() const;
	bool is_unlocked() const { return m_container.has_value(); }

	// First run: creates a new config file protected by `password`.
	void create(std::string_view password, const PBConfiguration& initial = PBConfiguration());

	// Unlocks and reads the config file. Throws ioexception, vault_format_exception,
	// wrong_password_exception or integrity_exception.
	void load(std::string_view password);

	// Writes the current configuration. Requires create() or load() first.
	void save();

	// Forgets the key and the decrypted configuration.
	void lock();

	const PBConfiguration& get_config() const;

	config_service& set_config(const PBConfiguration& n_config);
};

#endif /* CONFIGSERVICE_H_ */
