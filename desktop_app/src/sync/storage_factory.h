#ifndef PB_STORAGE_FACTORY_H_
#define PB_STORAGE_FACTORY_H_

#include "cloud_storage.h"
#include "http_transport.h"
#include "pb_types.h"

#include <memory>
#include <string>

namespace pb::sync {

// Builds the storage selected in the configuration. Returns nullptr for
// NO_SYNC. Throws pbexception(NOT_IMPLEMENTED) for engines not available yet,
// and authentication_exception(NOT_LINKED) when no token is configured.
// `http` must outlive the returned object.
std::unique_ptr<cloud_storage> make_cloud_storage(const PBConfiguration& config,
                                                  http_transport& http,
                                                  const std::string& dropbox_app_key);

} // namespace pb::sync

#endif // PB_STORAGE_FACTORY_H_
