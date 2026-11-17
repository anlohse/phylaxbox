#ifndef PB_DROPBOX_STORAGE_H_
#define PB_DROPBOX_STORAGE_H_

#include "sync/cloud_storage.h"
#include "sync/http_transport.h"

#include <chrono>
#include <functional>
#include <string>

namespace pb::sync {

// Dropbox "App folder" storage of the vault file.
class dropbox_storage : public cloud_storage {
public:
    using clock_fn = std::function<std::chrono::steady_clock::time_point()>;

    // Path inside the app folder (the app is registered with App Folder access).
    static constexpr const char* DEFAULT_PATH = "/vault.phylaxbox";

    dropbox_storage(http_transport& http, std::string app_key, std::string refresh_token,
                    std::string remote_path = DEFAULT_PATH,
                    clock_fn now = &std::chrono::steady_clock::now);

    std::optional<remote_file> download() override;
    std::string upload(byte_view data, const std::string& base_rev) override;
    void remove() override;

private:
    // Sends an authenticated request. Refreshes the access token when it is
    // missing or about to expire, and once more if Dropbox answers 401.
    http_response send(http_request req);
    void refresh();

    http_transport& m_http;
    std::string m_app_key;
    std::string m_refresh_token;
    std::string m_path;
    clock_fn m_now;

    std::string m_access_token;
    std::chrono::steady_clock::time_point m_expires_at{};
};

} // namespace pb::sync

#endif // PB_DROPBOX_STORAGE_H_
