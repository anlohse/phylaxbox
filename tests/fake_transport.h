#ifndef PB_FAKE_TRANSPORT_H_
#define PB_FAKE_TRANSPORT_H_

#include "sync/http_transport.h"
#include "models/pbexceptions.h"

#include <deque>
#include <functional>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace pb_test {

// Scripted http_transport: returns queued responses in order and records
// every request it receives.
class fake_transport : public pb::sync::http_transport {
public:
    std::vector<pb::sync::http_request> requests;

    fake_transport& respond(int status, std::string body,
                            std::map<std::string, std::string> headers = {}) {
        pb::sync::http_response r;
        r.status = status;
        r.body = std::move(body);
        r.headers = std::move(headers);
        m_queue.push_back([r](const pb::sync::http_request&) { return r; });
        return *this;
    }

    fake_transport& fail_network() {
        m_queue.push_back([](const pb::sync::http_request&) -> pb::sync::http_response {
            throw network_exception("simulated connection failure");
        });
        return *this;
    }

    fake_transport& token(const std::string& access, int expires_in = 14400,
                          const std::string& refresh = "") {
        std::string body = R"({"access_token":")" + access + R"(","token_type":"bearer","expires_in":)" +
                           std::to_string(expires_in);
        if (!refresh.empty()) body += R"(,"refresh_token":")" + refresh + "\"";
        body += R"(,"account_id":"dbid:test"})";
        return respond(200, body);
    }

    pb::sync::http_response post(const pb::sync::http_request& request) override {
        requests.push_back(request);
        if (m_queue.empty()) {
            throw std::logic_error("fake_transport: unexpected request to " + request.path);
        }
        auto next = m_queue.front();
        m_queue.pop_front();
        return next(request);
    }

    bool exhausted() const { return m_queue.empty(); }

    static std::string header(const pb::sync::http_request& r, const std::string& name) {
        for (const auto& [k, v] : r.headers) {
            if (k == name) return v;
        }
        return {};
    }

private:
    std::deque<std::function<pb::sync::http_response(const pb::sync::http_request&)>> m_queue;
};

// Splits "a=1&b=x%20y" into a map, percent-decoding values.
inline std::map<std::string, std::string> parse_form(const std::string& body) {
    auto decode = [](const std::string& s) {
        std::string out;
        for (std::size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '%' && i + 2 < s.size()) {
                out += static_cast<char>(std::stoi(s.substr(i + 1, 2), nullptr, 16));
                i += 2;
            } else {
                out += s[i];
            }
        }
        return out;
    };
    std::map<std::string, std::string> fields;
    std::size_t start = 0;
    while (start <= body.size()) {
        const auto amp = body.find('&', start);
        const auto pair = body.substr(start, amp == std::string::npos ? std::string::npos : amp - start);
        const auto eq = pair.find('=');
        if (eq != std::string::npos) fields[pair.substr(0, eq)] = decode(pair.substr(eq + 1));
        if (amp == std::string::npos) break;
        start = amp + 1;
    }
    return fields;
}

} // namespace pb_test

#endif // PB_FAKE_TRANSPORT_H_
