#ifndef PB_DROPBOX_OAUTH_H_
#define PB_DROPBOX_OAUTH_H_

#include "http_transport.h"

#include <chrono>
#include <string>

// OAuth 2 "authorization code + PKCE" for Dropbox (public client: the app key
// is not secret and no app secret is shipped). Offline access gives a
// long-lived refresh token, stored encrypted in the local config; access
// tokens are short-lived and only kept in memory.
namespace pb::sync::dropbox {

constexpr const char* AUTHORIZE_URL = "https://www.dropbox.com/oauth2/authorize";
constexpr const char* API_BASE = "https://api.dropboxapi.com";
constexpr const char* CONTENT_BASE = "https://content.dropboxapi.com";

struct pkce_pair {
    std::string verifier;  // 43 chars, base64url of 32 random bytes
    std::string challenge; // base64url(SHA-256(verifier)), method S256

    static pkce_pair generate();
    static std::string challenge_for(const std::string& verifier);
};

// Random, URL-safe anti-CSRF value for the `state` parameter.
std::string random_state();

// RFC 3986 percent-encoding of everything but unreserved characters.
std::string url_encode(const std::string& value);

std::string build_authorize_url(const std::string& app_key, const std::string& redirect_uri,
                                const pkce_pair& pkce, const std::string& state);

struct tokens {
    std::string access_token;
    std::string refresh_token; // empty on refresh responses
    std::chrono::seconds expires_in{0};
    std::string account_id;
};

// Exchanges the authorization code for tokens.
// Throws authentication_exception if Dropbox rejects the code.
tokens exchange_code(http_transport& http, const std::string& app_key, const std::string& code,
                     const std::string& code_verifier, const std::string& redirect_uri);

// Gets a fresh access token. Throws authentication_exception(NOT_LINKED) when
// the refresh token was revoked: the user must link Dropbox again.
tokens refresh_access_token(http_transport& http, const std::string& app_key,
                            const std::string& refresh_token);

} // namespace pb::sync::dropbox

#endif // PB_DROPBOX_OAUTH_H_
