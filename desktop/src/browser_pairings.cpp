#include "browser_pairings.h"

#include "crypto/crypto.h"
#include "storage/file_io.h"

#include <sodium.h>

#include <algorithm>
#include <stdexcept>

namespace pb::app {

namespace {

using json = secure_json;

std::string hex(const unsigned char* data, std::size_t size) {
    std::string out(size * 2 + 1, '\0');
    sodium_bin2hex(out.data(), out.size(), data, size);
    out.pop_back();
    return out;
}

} // namespace

secure_string base64_encode(const secure_string& bytes) {
    secure_string out(sodium_base64_ENCODED_LEN(bytes.size(), sodium_base64_VARIANT_ORIGINAL), '\0');
    sodium_bin2base64(out.data(), out.size(), reinterpret_cast<const unsigned char*>(bytes.data()),
                      bytes.size(), sodium_base64_VARIANT_ORIGINAL);
    out.pop_back(); // terminating NUL
    return out;
}

std::optional<secure_string> base64_decode(const secure_string& text, std::size_t expected) {
    secure_string out(expected, '\0');
    std::size_t len = 0;
    if (sodium_base642bin(reinterpret_cast<unsigned char*>(out.data()), out.size(), text.data(), text.size(),
                          nullptr, &len, nullptr, sodium_base64_VARIANT_ORIGINAL) != 0 ||
        len != expected) {
        return std::nullopt;
    }
    return out;
}

namespace {

bool valid_id(const std::string& id) {
    return id.size() == 32 && std::all_of(id.begin(), id.end(), [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}

std::string plain(const json& v) {
    if (!v.is_string()) return {};
    const auto& s = v.get_ref<const secure_string&>();
    return std::string(s.data(), s.size());
}

} // namespace

browser_pairings::browser_pairings(std::filesystem::path file) : m_file(std::move(file)) {
    try {
        const auto bytes = file_io::read_file(m_file);
        const json js = json::parse(bytes.begin(), bytes.end());
        if (!js.is_object() || js.value("version", 0) != 1) return;
        const auto it = js.find("clients");
        if (it == js.end() || !it->is_array()) return;
        for (const auto& c : *it) {
            if (!c.is_object() || m_clients.size() >= MAX_CLIENTS) continue;
            browser_client client;
            client.id = plain(c.value("id", json()));
            client.name = plain(c.value("name", json()));
            client.origin = plain(c.value("origin", json()));
            client.created_at = plain(c.value("createdAt", json()));
            client.last_used_at = plain(c.value("lastUsedAt", json()));
            const auto key_it = c.find("key");
            if (key_it == c.end() || !key_it->is_string()) continue;
            auto key = base64_decode(key_it->get_ref<const secure_string&>(), browser_client::KEY_BYTES);
            if (!valid_id(client.id) || client.origin.empty() || !key) continue;
            client.key = std::move(*key);
            m_clients.push_back(std::move(client));
        }
    } catch (...) {
        m_clients.clear(); // unreadable: nothing is paired
    }
}

std::filesystem::path browser_pairings::default_path() {
    return file_io::default_data_dir() / "browser-pairings.json";
}

browser_client browser_pairings::add(const std::string& name, const std::string& origin, const std::string& now) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_clients.size() >= MAX_CLIENTS) throw std::length_error("too many paired browsers");
    browser_client client;
    unsigned char id[16];
    crypto::random_bytes(id, sizeof(id));
    client.id = hex(id, sizeof(id));
    client.name = name;
    client.origin = origin;
    client.key.assign(browser_client::KEY_BYTES, '\0');
    crypto::random_bytes(reinterpret_cast<std::uint8_t*>(client.key.data()), client.key.size());
    client.created_at = now;
    m_clients.push_back(client);
    try {
        save();
    } catch (...) {
        m_clients.pop_back();
        throw;
    }
    return client;
}

std::optional<browser_client> browser_pairings::find(const std::string& id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& c : m_clients) {
        if (c.id == id) return c;
    }
    return std::nullopt;
}

bool browser_pairings::remove(const std::string& id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    const auto it = std::find_if(m_clients.begin(), m_clients.end(), [&](const auto& c) { return c.id == id; });
    if (it == m_clients.end()) return false;
    browser_client removed = std::move(*it);
    m_clients.erase(it);
    try {
        save();
    } catch (...) {
        m_clients.push_back(std::move(removed)); // still on disk: keep it listed
        throw;
    }
    return true;
}

void browser_pairings::touch(const std::string& id, const std::string& now) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& c : m_clients) {
        if (c.id == id) {
            c.last_used_at = now;
            try {
                save();
            } catch (...) {
                // Only a timestamp: not worth failing the connection.
            }
            return;
        }
    }
}

std::vector<browser_client> browser_pairings::list() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_clients;
}

void browser_pairings::save() const {
    json clients = json::array();
    for (const auto& c : m_clients) {
        clients.push_back({{"id", to_secure(c.id)},
                           {"name", to_secure(c.name)},
                           {"origin", to_secure(c.origin)},
                           {"key", base64_encode(c.key)},
                           {"createdAt", to_secure(c.created_at)},
                           {"lastUsedAt", to_secure(c.last_used_at)}});
    }
    const json js = {{"version", 1}, {"clients", std::move(clients)}};
    const secure_string text = js.dump(2);
    file_io::write_file_atomic(m_file, byte_view(view(text)));
}

} // namespace pb::app
