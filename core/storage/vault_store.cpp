#include "storage/vault_store.h"

#include "models/pbexceptions.h"
#include "storage/file_io.h"

#include <algorithm>
#include <string>
#include <system_error>
#include <utility>

namespace pb {

namespace {

// "2026-11-18T17:01:02.123Z" -> "20261118T170102123Z" (file-name safe, sorts by time).
std::string compact_timestamp(const std::string& rfc3339) {
    std::string out;
    for (const char c : rfc3339) {
        if (c != '-' && c != ':' && c != '.') out += c;
    }
    return out;
}

// "20261118T170102123Z" -> "2026-11-18T17:01:02.123Z"; empty if malformed.
std::string expand_timestamp(const std::string& compact) {
    if (compact.size() != 19 || compact[8] != 'T' || compact[18] != 'Z') return {};
    for (std::size_t i = 0; i < 18; ++i) {
        if (i != 8 && (compact[i] < '0' || compact[i] > '9')) return {};
    }
    return compact.substr(0, 4) + "-" + compact.substr(4, 2) + "-" + compact.substr(6, 2) + "T" +
           compact.substr(9, 2) + ":" + compact.substr(11, 2) + ":" + compact.substr(13, 2) + "." +
           compact.substr(15, 3) + "Z";
}

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

std::filesystem::path vault_store::backup_dir() const {
    return m_path.parent_path() / "backups";
}

void vault_store::set_backup_retention(std::size_t count) {
    m_backup_retention = count < 1 ? 1 : count;
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
    save(true);
}

void vault_store::save(bool force_backup) {
    require_unlocked();
    m_document->purge_tombstones(utc_now()); // ADR 0002: 180-day retention
    const secure_string json = m_document->to_json();
    const std::vector<std::uint8_t> file = m_container->seal(view(json));

    // 1. Decrypt what is about to be written, with the key in memory.
    {
        secure_bytes content;
        m_container->read_version(file, content);
        if (content.as_string_view() != view(json)) {
            throw pbexception(ErrorCodes::SAVE_VERIFICATION_FAILED,
                              "encrypted vault did not decrypt to the saved content");
        }
    }

    // 2. Keep the previous version (rate-limited unless forced).
    if (exists()) {
        bool due = force_backup || m_backup_interval.count() <= 0;
        if (!due) {
            const auto all = backups();
            const auto newest = all.empty() ? std::nullopt : utc_seconds(all.front().saved_at);
            const auto now = utc_seconds(utc_now());
            due = !newest || !now || *now - *newest >= m_backup_interval.count();
        }
        if (due) back_up_current_file();
    }

    // 3. Atomic replace, 4. read back.
    file_io::write_file_atomic(m_path, file);
    if (file_io::read_file(m_path) != file) {
        throw pbexception(ErrorCodes::SAVE_VERIFICATION_FAILED,
                          "vault file read back differs from what was written");
    }
}

void vault_store::back_up_current_file() {
    // Name it after the revision stored in the file on disk, read by
    // decrypting it with the key in memory (0 if it cannot be read).
    const auto current = file_io::read_file(m_path);
    std::uint64_t revision = 0;
    if (m_container) {
        secure_bytes ignored;
        try {
            revision = m_container->read_version(current, ignored);
        } catch (const pbexception&) {
            revision = 0; // not readable with this key: still keep a copy
        }
    }
    const std::string name = m_path.stem().string() + "-" + compact_timestamp(utc_now()) + "-r" +
                             std::to_string(revision) + m_path.extension().string();
    file_io::write_file_atomic(backup_dir() / name, current);
    prune_backups();
}

std::vector<vault_backup> vault_store::backups() const {
    std::vector<vault_backup> out;
    std::error_code ec;
    if (!std::filesystem::is_directory(backup_dir(), ec)) return out;

    const std::string prefix = m_path.stem().string() + "-";
    const std::string ext = m_path.extension().string();
    for (const auto& item : std::filesystem::directory_iterator(backup_dir(), ec)) {
        if (!item.is_regular_file(ec)) continue;
        const std::string name = item.path().filename().string();
        // <stem>-<19-char timestamp>-r<digits><ext>
        if (name.size() < prefix.size() + 19 + 3 + ext.size() || name.rfind(prefix, 0) != 0 ||
            name.compare(name.size() - ext.size(), ext.size(), ext) != 0) {
            continue;
        }
        const std::string middle =
            name.substr(prefix.size(), name.size() - prefix.size() - ext.size());
        const auto dash = middle.find("-r");
        if (dash != 19) continue;
        const std::string digits = middle.substr(21);
        if (digits.empty() || digits.find_first_not_of("0123456789") != std::string::npos) continue;
        const std::string saved_at = expand_timestamp(middle.substr(0, 19));
        if (saved_at.empty()) continue;

        vault_backup b;
        b.path = item.path();
        b.saved_at = saved_at;
        b.revision = std::stoull(digits);
        b.size = item.file_size(ec);
        out.push_back(std::move(b));
    }
    std::sort(out.begin(), out.end(), [](const vault_backup& a, const vault_backup& b) {
        if (a.saved_at != b.saved_at) return a.saved_at > b.saved_at;
        return a.revision > b.revision;
    });
    return out;
}

void vault_store::prune_backups() const {
    const auto all = backups();
    for (std::size_t i = m_backup_retention; i < all.size(); ++i) {
        std::error_code ec;
        std::filesystem::remove(all[i].path, ec); // best effort
    }
}

void vault_store::restore_backup(const std::filesystem::path& backup) {
    require_unlocked();
    const auto file = file_io::read_file(backup);
    secure_bytes content;
    m_container->read_version(file, content); // integrity + same vault, or throws
    vault_document restored = vault_document::from_json(content.as_string_view());
    m_document = std::move(restored);
    save(true); // a new revision; the version being replaced is backed up first
}

void vault_store::unlock_from_backup(std::string_view password,
                                     const std::filesystem::path& backup) {
    lock();
    const auto file = file_io::read_file(backup);
    secure_bytes content;
    auto container = vault_container::open(password, file, content_type::vault, content);
    load(std::move(content), std::move(container));

    if (exists()) {
        std::filesystem::path damaged = m_path;
        damaged += ".damaged-" + compact_timestamp(utc_now());
        std::error_code ec;
        std::filesystem::rename(m_path, damaged, ec);
        if (ec) {
            lock();
            throw ioexception(ErrorCodes::ERROR_WRITING, damaged.string());
        }
    }
    try {
        save();
    } catch (...) {
        lock();
        throw;
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
