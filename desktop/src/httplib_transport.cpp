#include "httplib_transport.h"

#include "models/pbexceptions.h"

#include <httplib.h>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <string>

namespace pb::app {

namespace {

// On Linux, cpp-httplib asks OpenSSL for its default CA locations, which for
// a statically linked (vcpkg) OpenSSL point inside the build tree instead of
// the distribution's trust store. Point it at the system bundle explicitly.
// (Windows uses the system certificate store; see httplib load_system_certs.)
const std::string& system_ca_bundle() {
    static const std::string path = [] {
#if defined(_WIN32) || defined(__APPLE__)
        return std::string();
#else
        for (const char* candidate : {"/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu
                                      "/etc/pki/tls/certs/ca-bundle.crt",   // Fedora/RHEL
                                      "/etc/ssl/ca-bundle.pem",             // openSUSE
                                      "/etc/ssl/cert.pem"}) {               // Alpine, Arch
            std::error_code ec;
            if (std::filesystem::is_regular_file(candidate, ec)) return std::string(candidate);
        }
        return std::string();
#endif
    }();
    return path;
}

} // namespace

httplib_transport::httplib_transport(std::chrono::seconds connect_timeout,
                                     std::chrono::seconds io_timeout)
    : m_connect_timeout(connect_timeout), m_io_timeout(io_timeout) {}

sync::http_response httplib_transport::post(const sync::http_request& request) {
    httplib::Client cli(request.base_url);
    if (!cli.is_valid()) {
        throw network_exception("invalid URL: " + request.base_url);
    }
    cli.enable_server_certificate_verification(true);
    if (!system_ca_bundle().empty()) {
        cli.set_ca_cert_path(system_ca_bundle());
    }
    cli.set_connection_timeout(static_cast<time_t>(m_connect_timeout.count()));
    cli.set_read_timeout(static_cast<time_t>(m_io_timeout.count()));
    cli.set_write_timeout(static_cast<time_t>(m_io_timeout.count()));
    cli.set_follow_location(false);

    httplib::Headers headers;
    for (const auto& [name, value] : request.headers) {
        headers.emplace(name, value);
    }

    const auto result = cli.Post(request.path, headers, request.body, request.content_type);
    if (!result) {
        throw network_exception(request.base_url + request.path + ": " +
                                httplib::to_string(result.error()));
    }

    sync::http_response response;
    response.status = result->status;
    response.body = result->body;
    for (const auto& [name, value] : result->headers) {
        std::string lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        response.headers[lower] = value;
    }
    return response;
}

} // namespace pb::app
