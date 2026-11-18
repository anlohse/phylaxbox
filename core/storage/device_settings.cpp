#include "storage/device_settings.h"

#include "storage/file_io.h"
#include "storage/vault_store.h"

#include <nlohmann/json.hpp>

#include <stdexcept>

namespace pb {

namespace {

using json = nlohmann::json;

bool valid_theme(const std::string& t) { return t == "system" || t == "light" || t == "dark"; }
bool valid_language(const std::string& l) { return l == "system" || l == "pt-BR" || l == "en"; }

std::filesystem::path from_utf8(const std::string& s) {
    return std::filesystem::path(std::u8string(s.begin(), s.end()));
}

} // namespace

std::filesystem::path device_settings::default_path() {
    return file_io::default_data_dir() / "settings.json";
}

std::filesystem::path device_settings::effective_vault_path() const {
    return vault_path.empty() ? vault_store::default_path() : from_utf8(vault_path);
}

void device_settings::validate() const {
    if (!valid_theme(theme)) throw std::invalid_argument("invalid theme");
    if (!valid_language(language)) throw std::invalid_argument("invalid language");
    if (backup_retention < MIN_BACKUP_RETENTION || backup_retention > MAX_BACKUP_RETENTION) {
        throw std::invalid_argument("invalid backup retention");
    }
    if (!vault_path.empty() && !from_utf8(vault_path).is_absolute()) {
        throw std::invalid_argument("vault path must be absolute");
    }
}

device_settings device_settings::load(const std::filesystem::path& file) {
    device_settings s;
    json js;
    try {
        const auto bytes = file_io::read_file(file);
        js = json::parse(bytes.begin(), bytes.end());
    } catch (...) {
        return s; // missing or not JSON: defaults
    }
    if (!js.is_object()) return s;
    const device_settings defaults;
    auto str = [&](const char* key, std::string& target, bool (*ok)(const std::string&)) {
        const auto it = js.find(key);
        if (it != js.end() && it->is_string() && ok(it->get<std::string>())) target = it->get<std::string>();
    };
    str("theme", s.theme, valid_theme);
    str("language", s.language, valid_language);
    str("vaultPath", s.vault_path, [](const std::string& p) {
        return !p.empty() && from_utf8(p).is_absolute();
    });
    if (const auto it = js.find("backupRetention"); it != js.end() && it->is_number_unsigned()) {
        const auto n = it->get<std::size_t>();
        if (n >= MIN_BACKUP_RETENTION && n <= MAX_BACKUP_RETENTION) s.backup_retention = n;
    }
    return s;
}

void device_settings::save(const std::filesystem::path& file) const {
    validate();
    json js = {{"theme", theme},
               {"language", language},
               {"backupRetention", backup_retention}};
    if (!vault_path.empty()) js["vaultPath"] = vault_path;
    file_io::write_file_atomic(file, std::string_view(js.dump(2) + "\n"));
}

} // namespace pb
