#include "dropbox_storage.h"

#include "dropbox_oauth.h"
#include "pbexceptions.h"

#include <nlohmann/json.hpp>

#include <utility>

namespace pb::sync {

namespace {

// Refresh this long before the reported expiry to absorb clock skew and latency.
constexpr std::chrono::seconds EXPIRY_MARGIN{60};

// Dropbox-API-Arg must be ASCII: dump with ensure_ascii.
std::string api_arg(const nlohmann::json& js) { return js.dump(-1, ' ', true); }

std::string error_summary(const http_response& res) {
    try {
        return nlohmann::json::parse(res.body).value("error_summary", std::string());
    } catch (const nlohmann::json::exception&) {
        return res.body.substr(0, 200); // plain-text errors (400)
    }
}

bool starts_with(const std::string& s, const char* prefix) {
    return s.rfind(prefix, 0) == 0;
}

[[noreturn]] void fail(const http_response& res) {
    throwHttpException(res.status, error_summary(res));
}

} // namespace

dropbox_storage::dropbox_storage(http_transport& http, std::string app_key,
                                 std::string refresh_token, std::string remote_path, clock_fn now)
    : m_http(http), m_app_key(std::move(app_key)), m_refresh_token(std::move(refresh_token)),
      m_path(std::move(remote_path)), m_now(std::move(now)) {}

void dropbox_storage::refresh() {
    const auto t = dropbox::refresh_access_token(m_http, m_app_key, m_refresh_token);
    m_access_token = t.access_token;
    m_expires_at = m_now() + t.expires_in - EXPIRY_MARGIN;
}

http_response dropbox_storage::send(http_request req) {
    if (m_access_token.empty() || m_now() >= m_expires_at) {
        refresh();
    }
    const auto auth_index = req.headers.size();
    req.headers.emplace_back("Authorization", "Bearer " + m_access_token);
    http_response res = m_http.post(req);
    if (res.status == 401) {
        // Token revoked server-side or expired early: one refresh, one retry.
        refresh();
        req.headers[auth_index].second = "Bearer " + m_access_token;
        res = m_http.post(req);
    }
    return res;
}

std::optional<remote_file> dropbox_storage::download() {
    http_request req;
    req.base_url = dropbox::CONTENT_BASE;
    req.path = "/2/files/download";
    req.headers.emplace_back("Dropbox-API-Arg", api_arg({{"path", m_path}}));
    const http_response res = send(std::move(req));

    if (res.status == 200) {
        remote_file f;
        f.data.assign(res.body.begin(), res.body.end());
        try {
            f.rev = nlohmann::json::parse(res.header("dropbox-api-result")).at("rev").get<std::string>();
        } catch (const nlohmann::json::exception& e) {
            throw http_exception(ErrorCodes::OTHER_4XX_ERROR,
                                 std::string("missing revision in download response: ") + e.what());
        }
        return f;
    }
    if (res.status == 409 && starts_with(error_summary(res), "path/not_found")) {
        return std::nullopt;
    }
    fail(res);
}

std::string dropbox_storage::upload(byte_view data, const std::string& base_rev) {
    nlohmann::json mode;
    if (base_rev.empty()) {
        mode = "add"; // with autorename=false: conflict if the file already exists
    } else {
        mode = {{".tag", "update"}, {"update", base_rev}};
    }

    http_request req;
    req.base_url = dropbox::CONTENT_BASE;
    req.path = "/2/files/upload";
    req.headers.emplace_back("Dropbox-API-Arg", api_arg({{"path", m_path},
                                                         {"mode", mode},
                                                         {"autorename", false},
                                                         {"mute", true},
                                                         {"strict_conflict", true}}));
    req.body.assign(reinterpret_cast<const char*>(data.data), data.size);
    req.content_type = "application/octet-stream";
    const http_response res = send(std::move(req));

    if (res.status == 200) {
        try {
            return nlohmann::json::parse(res.body).at("rev").get<std::string>();
        } catch (const nlohmann::json::exception& e) {
            throw http_exception(ErrorCodes::OTHER_4XX_ERROR,
                                 std::string("missing revision in upload response: ") + e.what());
        }
    }
    if (res.status == 409) {
        const std::string summary = error_summary(res);
        if (starts_with(summary, "path/conflict")) {
            throw sync_conflict_exception(summary);
        }
    }
    fail(res);
}

void dropbox_storage::remove() {
    http_request req;
    req.base_url = dropbox::API_BASE;
    req.path = "/2/files/delete_v2";
    req.body = nlohmann::json{{"path", m_path}}.dump();
    req.content_type = "application/json";
    const http_response res = send(std::move(req));

    if (res.status == 200) return;
    if (res.status == 409 && starts_with(error_summary(res), "path_lookup/not_found")) return;
    fail(res);
}

} // namespace pb::sync
