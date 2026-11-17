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
	NO_SYNC = 0, // vault kept only on this device
	DROPBOX = 1,
	G_DRIVE = 2
};

struct PBConfiguration {
	sync_engine_t sync_engine = NO_SYNC;
	std::string sync_token;
};

#define LOCAL_PORT 8881

#endif /* PB_TYPES_H_ */
