#ifndef PB_HTTP_TRANSPORT_H_
#define PB_HTTP_TRANSPORT_H_

#include <map>
#include <string>
#include <utility>
#include <vector>

namespace pb::sync {

struct http_request {
    std::string base_url; // scheme://host[:port], e.g. "https://api.dropboxapi.com"
    std::string path;     // "/2/files/upload"
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    std::string content_type; // empty: no Content-Type header is sent
};

struct http_response {
    int status = 0;
    std::map<std::string, std::string> headers; // names lower-cased
    std::string body;

    // `lower_name` must be lower case. Returns "" when absent.
    std::string header(const std::string& lower_name) const {
        const auto it = headers.find(lower_name);
        return it == headers.end() ? std::string() : it->second;
    }
};

// Minimal HTTP client abstraction so the cloud clients can be unit-tested
// without network access. Implementations must verify TLS certificates.
class http_transport {
public:
    virtual ~http_transport() = default;

    // Returns the response for any HTTP status. Throws network_exception when
    // no response was received (DNS, TLS, connection reset, timeout).
    virtual http_response post(const http_request& request) = 0;
};

} // namespace pb::sync

#endif // PB_HTTP_TRANSPORT_H_
