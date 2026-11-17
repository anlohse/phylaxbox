/*
 * pb_types.h
 *
 *  Created on: 16 de fev. de 2025
 *      Author: alanl
 */

#ifndef PB_TYPES_H_
#define PB_TYPES_H_

#include <string>

enum sync_engine_t {
	DROPOX = 1,
	G_DRIVE = 2
};

struct PBConfiguration {
	sync_engine_t sync_engine;
	std::string sync_token;
	PBConfiguration() {
	}
	PBConfiguration(const PBConfiguration& o): 
		sync_engine(o.sync_engine), 
		sync_token(o.sync_token) { }
};

#define LOCAL_PORT 8881

#endif /* PB_TYPES_H_ */
