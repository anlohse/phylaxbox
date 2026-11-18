#ifndef PB_DEVICE_ID_H_
#define PB_DEVICE_ID_H_

#include <filesystem>
#include <string>

namespace pb {

// Identifier of this installation, recorded on every change to the vault
// (spec §4.5 deviceId) for synchronization. Random, not secret, not derived
// from hardware: stored in plain text so it survives vault re-creation.
//
// Reads `file` (default <data dir>/device-id); creates it with a new UUID
// when missing or not a valid UUID. Throws ioexception if it cannot write.
std::string load_or_create_device_id(const std::filesystem::path& file);
std::filesystem::path default_device_id_path();

} // namespace pb

#endif // PB_DEVICE_ID_H_
