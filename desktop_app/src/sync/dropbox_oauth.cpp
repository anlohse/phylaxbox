#include "dropbox_oauth.h"

#include "crypto.h"
#include "pbexceptions.h"

#include <nlohmann/json.hpp>
#include <sodium.h>

#include <array>

namespace pb::sync::dropbox {

namespace {

std::string base64url(const unsigned char* data, std::size_t size) {
    std::string out(sodium_base64_ENCODED_LEN(size, sodium_base64_VARIANT_URLSAFE_NO_PADDING), '\0');
    sodium_bin2base64(out.data(), out.size(), data, size, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    out.resize(std::char_traits<char>::length(out.c_str()));
    return out;
}

std::string random_token(std::size_t bytes) {
    std::vector<unsigned char> buf(bytes);
    crypto::random_bytes(buf.data(), buf.size());
    return base64url(buf.data(), buf.size());
}

std::string form_encode(std::initializer_list<std::pair<const char*, std::string>> fields) {
    std::string body;
    for (const auto& [k, v] : fields) {
        if (!body.empty()) body += '&';
        body += k;
        body += '=';
        body += url_encode(v);
    }
    return body;
}

tokens post_token_request(http_transport& http, std::string body, bool is_refresh) {
    http_request req;
    req.base_url = API_BASE;
    req.path = "/oauth2/token";
    req.body = std::move(body);
    req.content_type = "application/x-www-form-urlencoded";
    const http_response res = http.post(req);

    if (res.status == 200) {
        try {
            const auto js = nlohmann::json::parse(res.body);
            tokens t;
            t.access_token = js.at("access_token").get<std::string>();
            t.refresh_token = js.value("refresh_token", std::string());
            t.expires_in = std::chrono::seconds(js.value("expires_in", 0));
            t.account_id = js.value("account_id", std::string());
            if (t.access_token.empty()) throw std::runtime_error("empty access token");
            return t;
        } catch (const std::exception& e) {
            throw http_exception(ErrorCodes::OTHER_4XX_ERROR,
                                 std::string("unexpected token response: ") + e.what());
        }
    }

    // 400 {"error": "invalid_grant", ...}: code expired/used, or refresh token revoked.
    std::string error;
    try {
        error = nlohmann::json::parse(res.body).value("error", std::string());
    } catch (const nlohmann::json::exception&) {
    }
    if (res.status == 400 || res.status == 401) {
        throw authentication_exception(
            is_refresh ? ErrorCodes::NOT_LINKED : ErrorCodes::UNAUTHORIZED,
            error.empty() ? "token request rejected" : error);
    }
    throwHttpException(res.status, error);
}

} // namespace

pkce_pair pkce_pair::generate() {
    pkce_pair p;
    p.verifier = random_token(32);
    p.challenge = challenge_for(p.verifier);
    return p;
}

std::string pkce_pair::challenge_for(const std::string& verifier) {
    crypto::ensure_initialized();
    std::array<unsigned char, crypto_hash_sha256_BYTES> digest{};
    crypto_hash_sha256(digest.data(), reinterpret_cast<const unsigned char*>(verifier.data()),
                       verifier.size());
    return base64url(digest.data(), digest.size());
}

std::string random_state() { return random_token(24); }

std::string url_encode(const std::string& value) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    out.reserve(value.size() * 3);
    for (const unsigned char c : value) {
        const bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                                (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' ||
                                c == '~';
        if (unreserved) {
            out += static_cast<char>(c);
        } else {
            out += '%';
            out += hex[c >> 4];
            out += hex[c & 0xF];
        }
    }
    return out;
}

std::string build_authorize_url(const std::string& app_key, const std::string& redirect_uri,
                                const pkce_pair& pkce, const std::string& state) {
    return std::string(AUTHORIZE_URL) + "?" +
           form_encode({{"client_id", app_key},
                        {"response_type", "code"},
                        {"token_access_type", "offline"},
                        {"code_challenge", pkce.challenge},
                        {"code_challenge_method", "S256"},
                        {"redirect_uri", redirect_uri},
                        {"state", state}});
}

tokens exchange_code(http_transport& http, const std::string& app_key, const std::string& code,
                     const std::string& code_verifier, const std::string& redirect_uri) {
    tokens t = post_token_request(http,
                                  form_encode({{"grant_type", "authorization_code"},
                                               {"code", code},
                                               {"code_verifier", code_verifier},
                                               {"client_id", app_key},
                                               {"redirect_uri", redirect_uri}}),
                                  false);
    if (t.refresh_token.empty()) {
        throw http_exception(ErrorCodes::OTHER_4XX_ERROR,
                             "Dropbox did not return a refresh token (offline access)");
    }
    return t;
}

tokens refresh_access_token(http_transport& http, const std::string& app_key,
                            const std::string& refresh_token) {
    if (refresh_token.empty()) {
        throw authentication_exception(ErrorCodes::NOT_LINKED, "Dropbox is not linked");
    }
    return post_token_request(http,
                              form_encode({{"grant_type", "refresh_token"},
                                           {"refresh_token", refresh_token},
                                           {"client_id", app_key}}),
                              true);
}

} // namespace pb::sync::dropbox
