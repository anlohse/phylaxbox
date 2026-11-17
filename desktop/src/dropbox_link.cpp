#include "dropbox_link.h"

#include "sync/dropbox_oauth.h"
#include "oauth_loopback.h"
#include "models/pbexceptions.h"

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#endif

namespace pb::app {

std::string link_dropbox(sync::http_transport& http, const std::string& app_key,
                         const std::function<bool(const std::string& url)>& open_browser,
                         int port, std::chrono::seconds timeout) {
    if (app_key.empty()) {
        throw pbexception(ErrorCodes::NOT_IMPLEMENTED,
                          "this build has no Dropbox app key (PB_DROPBOX_APP_KEY)");
    }
    const auto pkce = sync::dropbox::pkce_pair::generate();
    const auto state = sync::dropbox::random_state();

    oauth_loopback_receiver receiver(port);
    receiver.start(state);
    const std::string redirect_uri = receiver.redirect_uri();

    const std::string url =
        sync::dropbox::build_authorize_url(app_key, redirect_uri, pkce, state);
    if (!open_browser(url)) {
        throw pbexception(ErrorCodes::NETWORK_ERROR, "could not open the browser");
    }

    const std::string code = receiver.wait_for_code(timeout);
    receiver.stop();

    return sync::dropbox::exchange_code(http, app_key, code, pkce.verifier, redirect_uri)
        .refresh_token;
}

bool open_in_default_browser(const std::string& url) {
    if (url.rfind("https://", 0) != 0) {
        return false; // only ever hand https URLs to the shell
    }
#ifdef _WIN32
    const int wide_len = MultiByteToWideChar(CP_UTF8, 0, url.c_str(), -1, nullptr, 0);
    if (wide_len <= 0) return false;
    std::wstring wide(static_cast<std::size_t>(wide_len), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, url.c_str(), -1, wide.data(), wide_len);
    const auto rc = reinterpret_cast<INT_PTR>(
        ShellExecuteW(nullptr, L"open", wide.c_str(), nullptr, nullptr, SW_SHOWNORMAL));
    return rc > 32;
#else
    (void)url;
    return false; // TODO: xdg-open / open on Linux and macOS
#endif
}

} // namespace pb::app
