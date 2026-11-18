#include "storage/vault_store.h"

#include "models/pbexceptions.h"
#include "storage/file_io.h"

#include <string>
#include <utility>

namespace pb {

namespace {

void check_password(std::string_view password) {
    if (vault_store::password_length(password) < vault_store::MIN_PASSWORD_CHARS) {
        throw pbexception(ErrorCodes::WEAK_PASSWORD,
                          "the master password must have at least " +
                              std::to_string(vault_store::MIN_PASSWORD_CHARS) + " characters");
    }
}

} // namespace

vault_store::vault_store(std::filesystem::path file, crypto::kdf_params kdf)
    : m_path(std::move(file)), m_kdf(kdf) {}

std::filesystem::path vault_store::default_path() {
    return file_io::default_data_dir() / "vault.phylaxbox";
}

std::filesystem::path vault_store::backup_path() const {
    std::filesystem::path p = m_path;
    p += ".bak";
    return p;
}

bool vault_store::exists() const {
    std::error_code ec;
    return std::filesystem::is_regular_file(m_path, ec);
}

std::size_t vault_store::password_length(std::string_view utf8) {
    std::size_t n = 0;
    for (const unsigned char c : utf8) {
        if ((c & 0xC0) != 0x80) ++n; // count lead bytes, skip continuation bytes
    }
    return n;
}

std::optional<recovery_key> vault_store::create(std::string_view password,
                                                bool with_recovery_key) {
    if (exists()) {
        throw pbexception(ErrorCodes::VAULT_EXISTS, "a vault already exists at this location");
    }
    check_password(password);

    vault_container container = vault_container::create(password, content_type::vault, m_kdf);
    std::optional<recovery_key> key;
    if (with_recovery_key) key = container.add_recovery_key();

    m_container = std::move(container);
    m_document = vault_document{};
    try {
        save();
    } catch (...) {
        lock();
        throw;
    }
    return key;
}

void vault_store::load(secure_bytes&& content, vault_container&& container) {
    vault_document doc = vault_document::from_json(content.as_string_view());
    m_container = std::move(container);
    m_document = std::move(doc);
}

void vault_store::unlock(std::string_view password) {
    lock();
    const auto file = file_io::read_file(m_path);
    secure_bytes content;
    auto container = vault_container::open(password, file, content_type::vault, content);
    load(std::move(content), std::move(container));
}

void vault_store::unlock_with_recovery_key(const recovery_key& key) {
    lock();
    const auto file = file_io::read_file(m_path);
    secure_bytes content;
    auto container =
        vault_container::open_with_recovery_key(key, file, content_type::vault, content);
    load(std::move(content), std::move(container));
}

void vault_store::change_password(std::string_view new_password) {
    require_unlocked();
    check_password(new_password);
    m_container->change_password(new_password, m_kdf);
    save();
}

void vault_store::save() {
    require_unlocked();
    const std::string json = m_document->to_json();
    const std::vector<std::uint8_t> file = m_container->seal(json);

    // 1. Decrypt what is about to be written, with the key in memory.
    {
        secure_bytes content;
        m_container->read_version(file, content);
        if (content.as_string_view() != json) {
            throw pbexception(ErrorCodes::SAVE_VERIFICATION_FAILED,
                              "encrypted vault did not decrypt to the saved content");
        }
    }

    // 2. Keep the previous version.
    if (exists()) {
        file_io::write_file_atomic(backup_path(), file_io::read_file(m_path));
    }

    // 3. Atomic replace, 4. read back.
    file_io::write_file_atomic(m_path, file);
    if (file_io::read_file(m_path) != file) {
        throw pbexception(ErrorCodes::SAVE_VERIFICATION_FAILED,
                          "vault file read back differs from what was written");
    }
}

void vault_store::lock() {
    m_container.reset();
    m_document.reset();
}

void vault_store::require_unlocked() const {
    if (!m_container || !m_document) {
        throw pbexception(ErrorCodes::VAULT_LOCKED, "vault is locked");
    }
}

vault_document& vault_store::document() {
    require_unlocked();
    return *m_document;
}

const vault_document& vault_store::document() const {
    require_unlocked();
    return *m_document;
}

const vault_container& vault_store::container() const {
    require_unlocked();
    return *m_container;
}

} // namespace pb
