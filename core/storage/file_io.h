#ifndef PB_FILE_IO_H_
#define PB_FILE_IO_H_

#include "crypto/secure_bytes.h"

#include <cstdint>
#include <filesystem>
#include <vector>

namespace pb::file_io {

// Reads the whole file. Throws ioexception(FILE_NOT_FOUND / ERROR_READING).
std::vector<std::uint8_t> read_file(const std::filesystem::path& path);

// Writes to "<path>.tmp" in the same directory, flushes it to disk and renames
// it over `path`, so a crash never leaves a half-written vault. Creates the
// parent directory if needed. On POSIX systems the file is readable and
// writable by its owner only (0600). Throws ioexception.
void write_file_atomic(const std::filesystem::path& path, byte_view data);

// Per-user, per-device data directory:
//   Windows: %LOCALAPPDATA%\PhylaxBox
//   macOS:   ~/Library/Application Support/PhylaxBox
//   other:   $XDG_DATA_HOME/phylaxbox or ~/.local/share/phylaxbox
std::filesystem::path default_data_dir();

} // namespace pb::file_io

#endif // PB_FILE_IO_H_
