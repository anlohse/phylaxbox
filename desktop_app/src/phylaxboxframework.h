/*
 * phylaxboxframework.h
 *
 *  Created on: 15 de fev. de 2025
 *      Author: alanl
 */

#ifndef PHYLAXBOXFRAMEWORK_H_
#define PHYLAXBOXFRAMEWORK_H_

#include <string>

enum sync_engine_t {
	DROPOX = 1,
	G_DRIVE = 2
};

struct PBConfiguration {
	sync_engine_t sync_engine;
	char sync_token[128];
};

class phylaxbox_framework {
public:
	phylaxbox_framework();
	virtual ~phylaxbox_framework();

	void init();

	void configure(const PBConfiguration& newCfg);

	bool login_n_sync(const std::string& password);
};

#endif /* PHYLAXBOXFRAMEWORK_H_ */
