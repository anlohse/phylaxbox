#ifndef PB_DROPBOX_LINK_H_
#define PB_DROPBOX_LINK_H_

#include "http_transport.h"

#include <chrono>
#include <functional>
#include <string>

namespace pb::app {

// Full "Link Dropbox" flow: start the loopback listener, open the browser on
// Dropbox's consent page, wait for the redirect, exchange the code (PKCE).
// Returns the refresh token to store in PBConfiguration::sync_token.
//
// `open_browser` receives the authorization URL; return false if it could not
// be opened (the caller may then show the URL to the user).
std::string link_dropbox(sync::http_transport& http, const std::string& app_key,
                         const std::function<bool(const std::string& url)>& open_browser,
                         int port, std::chrono::seconds timeout = std::chrono::minutes(5));

// Opens `url` in the user's default browser.
bool open_in_default_browser(const std::string& url);

} // namespace pb::app

#endif // PB_DROPBOX_LINK_H_
