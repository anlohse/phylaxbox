/*
 * syncclients.h
 *
 *  Created on: 16 de fev. de 2025
 *      Author: alanl
 */

#ifndef SYNCCLIENTS_H_
#define SYNCCLIENTS_H_

#include "pb_types.h"
#include <memory>

namespace __interfaces {

	class _sync_client {
	public:
		_sync_client() { }
		virtual ~_sync_client() { }

		virtual void init(const PBConfiguration& config) = 0;

		virtual bool load(const std::string& dest_file) = 0;

		virtual bool send(const std::string& source_file) = 0;

		virtual void remove() = 0;

		virtual void startLocalserver() = 0;

		virtual bool authenticate() = 0;

		virtual void stopLocalserver() = 0;
	};

}

class sync_client : public __interfaces::_sync_client {
private:

	std::unique_ptr<__interfaces::_sync_client> _client;

	sync_client(const sync_engine_t& engine_type);

public:

	static sync_client create_client(const sync_engine_t& engine_type);

	sync_client(const sync_client& other) = delete;

	sync_client(sync_client&& other) noexcept;

	virtual ~sync_client();

	virtual void init(const PBConfiguration& config);

	virtual bool load(const std::string& dest_file);

	virtual bool send(const std::string& source_file);

	virtual void remove();

	virtual void startLocalserver();

	virtual bool authenticate();

	virtual void stopLocalserver();

	sync_client& operator=(sync_client&& other);

	sync_client& operator=(const sync_client& other) = delete;

};



#endif /* SYNCCLIENTS_H_ */
