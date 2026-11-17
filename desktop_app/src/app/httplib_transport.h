#ifndef PB_HTTPLIB_TRANSPORT_H_
#define PB_HTTPLIB_TRANSPORT_H_

#include "http_transport.h"

#include <chrono>

namespace pb::app {

// http_transport over cpp-httplib + OpenSSL. HTTPS certificates are verified
// against the OS trust store (cpp-httplib loads the Windows ROOT/CA stores).
class httplib_transport : public sync::http_transport {
public:
    explicit httplib_transport(std::chrono::seconds connect_timeout = std::chrono::seconds(10),
                               std::chrono::seconds io_timeout = std::chrono::seconds(60));

    sync::http_response post(const sync::http_request& request) override;

private:
    std::chrono::seconds m_connect_timeout;
    std::chrono::seconds m_io_timeout;
};

} // namespace pb::app

#endif // PB_HTTPLIB_TRANSPORT_H_
