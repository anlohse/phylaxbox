#include "storage/device_id.h"

#include "models/pbexceptions.h"
#include "models/vault_document.h"
#include "storage/file_io.h"

#include <string>

namespace pb {

std::filesystem::path default_device_id_path() {
    return file_io::default_data_dir() / "device-id";
}

std::string load_or_create_device_id(const std::filesystem::path& file) {
    try {
        const auto bytes = file_io::read_file(file);
        std::string id(bytes.begin(), bytes.end());
        while (!id.empty() && (id.back() == '\n' || id.back() == '\r' || id.back() == ' ')) {
            id.pop_back();
        }
        if (is_canonical_uuid(id)) return id;
    } catch (const ioexception&) {
        // missing or unreadable: create below
    }
    const std::string id = new_uuid();
    file_io::write_file_atomic(file, std::string_view(id + "\n"));
    return id;
}

} // namespace pb
