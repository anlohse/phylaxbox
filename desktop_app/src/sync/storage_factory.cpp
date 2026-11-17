#include "storage_factory.h"

#include "dropbox_storage.h"
#include "pbexceptions.h"

namespace pb::sync {

std::unique_ptr<cloud_storage> make_cloud_storage(const PBConfiguration& config,
                                                  http_transport& http,
                                                  const std::string& dropbox_app_key) {
    switch (config.sync_engine) {
    case NO_SYNC:
        return nullptr;
    case DROPBOX:
        if (config.sync_token.empty()) {
            throw authentication_exception(ErrorCodes::NOT_LINKED, "Dropbox is not linked");
        }
        if (dropbox_app_key.empty()) {
            throw pbexception(ErrorCodes::NOT_IMPLEMENTED,
                              "this build has no Dropbox app key (PB_DROPBOX_APP_KEY)");
        }
        return std::make_unique<dropbox_storage>(http, dropbox_app_key, config.sync_token);
    case G_DRIVE:
        break;
    }
    throw pbexception(ErrorCodes::NOT_IMPLEMENTED, "sync engine not available yet");
}

} // namespace pb::sync
