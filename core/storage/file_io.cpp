#include "storage/file_io.h"

#include "models/pbexceptions.h"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <memory>
#include <system_error>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace pb::file_io {

namespace {

std::string display(const fs::path& p) {
    const auto u8 = p.u8string(); // std::string in C++17
    return std::string(u8.begin(), u8.end());
}

struct file_closer {
    void operator()(std::FILE* f) const {
        if (f) std::fclose(f);
    }
};

std::FILE* open_for_write(const fs::path& p) {
#ifdef _WIN32
    return ::_wfopen(p.c_str(), L"wb");
#else
    return std::fopen(p.c_str(), "wb");
#endif
}

bool flush_to_disk(std::FILE* f) {
    if (std::fflush(f) != 0) return false;
#ifdef _WIN32
    return ::_commit(::_fileno(f)) == 0;
#else
    return ::fsync(::fileno(f)) == 0;
#endif
}

} // namespace

std::vector<std::uint8_t> read_file(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw ioexception(ErrorCodes::FILE_NOT_FOUND, display(path));
    }
    std::vector<std::uint8_t> data((std::istreambuf_iterator<char>(in)),
                                   std::istreambuf_iterator<char>());
    if (in.bad()) {
        throw ioexception(ErrorCodes::ERROR_READING, display(path));
    }
    return data;
}

void write_file_atomic(const fs::path& path, byte_view data) {
    std::error_code ec;
    if (path.has_parent_path()) {
        fs::create_directories(path.parent_path(), ec);
        if (ec) {
            throw ioexception(ErrorCodes::CANT_CREATE_FILE, display(path.parent_path()));
        }
    }

    fs::path tmp = path;
    tmp += ".tmp";
    {
        std::unique_ptr<std::FILE, file_closer> f(open_for_write(tmp));
        if (!f) {
            throw ioexception(ErrorCodes::CANT_CREATE_FILE, display(tmp));
        }
        const bool ok = (data.size == 0 || std::fwrite(data.data, 1, data.size, f.get()) == data.size) &&
                        flush_to_disk(f.get());
        if (!ok) {
            f.reset();
            fs::remove(tmp, ec);
            throw ioexception(ErrorCodes::ERROR_WRITING, display(tmp));
        }
    }

    fs::rename(tmp, path, ec); // replaces an existing file
    if (ec) {
        fs::remove(tmp, ec);
        throw ioexception(ErrorCodes::ERROR_WRITING, display(path));
    }
}

fs::path default_data_dir() {
#ifdef _WIN32
    if (const wchar_t* local = ::_wgetenv(L"LOCALAPPDATA"); local && *local) {
        return fs::path(local) / L"PhylaxBox";
    }
#elif defined(__APPLE__)
    if (const char* home = std::getenv("HOME"); home && *home) {
        return fs::path(home) / "Library" / "Application Support" / "PhylaxBox";
    }
#else
    if (const char* xdg = std::getenv("XDG_DATA_HOME"); xdg && *xdg) {
        return fs::path(xdg) / "phylaxbox";
    }
    if (const char* home = std::getenv("HOME"); home && *home) {
        return fs::path(home) / ".local" / "share" / "phylaxbox";
    }
#endif
    throw ioexception(ErrorCodes::FILE_NOT_FOUND, "user data directory");
}

} // namespace pb::file_io
