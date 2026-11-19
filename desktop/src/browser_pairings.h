#ifndef PB_BROWSER_PAIRINGS_H_
#define PB_BROWSER_PAIRINGS_H_

#include "crypto/secure_allocator.h"

#include <cstddef>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace pb::app {

// A browser extension the user approved on this computer (spec §8.4).
struct browser_client {
    static constexpr std::size_t KEY_BYTES = 32;

    std::string id;       // 32 hex characters
    std::string name;     // what the extension called itself ("Chrome", "Firefox")
    std::string origin;   // extension origin reported by the browser
    secure_string key;    // 32 random bytes shared with the extension (HMAC-SHA256)
    std::string created_at;   // RFC 3339 UTC
    std::string last_used_at; // RFC 3339 UTC, empty until the first connection
};

// Pairing keys of this device, in <data dir>/browser-pairings.json (owner
// only). They let an extension prove it was approved; they do not decrypt
// anything, and they stay on this device (not in the vault, so they are not
// synchronized). Thread-safe.
class browser_pairings {
public:
    static constexpr std::size_t MAX_CLIENTS = 20;

    // Loads the file; a missing or invalid file means no paired browsers.
    explicit browser_pairings(std::filesystem::path file);

    static std::filesystem::path default_path();

    // Creates a client with a fresh id and key, and saves. Throws
    // std::length_error when MAX_CLIENTS are already paired, ioexception when
    // the file cannot be written.
    browser_client add(const std::string& name, const std::string& origin, const std::string& now);

    std::optional<browser_client> find(const std::string& id) const;
    // Removes and saves; false if there was no such client.
    bool remove(const std::string& id);
    // Records a successful connection (best effort).
    void touch(const std::string& id, const std::string& now);

    std::vector<browser_client> list() const;

private:
    void save() const; // with m_mutex held

    std::filesystem::path m_file;
    mutable std::mutex m_mutex;
    std::vector<browser_client> m_clients;
};

// Standard base64 (with padding) of raw bytes, and back. base64_decode
// returns nullopt unless the text decodes to exactly `expected` bytes.
secure_string base64_encode(const secure_string& bytes);
std::optional<secure_string> base64_decode(const secure_string& text, std::size_t expected);

} // namespace pb::app

#endif // PB_BROWSER_PAIRINGS_H_
