#include "ipc/local_channel.h"

#include <array>
#include <atomic>
#include <cstring>
#include <mutex>
#include <utility>

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#else
#include <cerrno>
#include <cstdlib>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#endif

namespace pb::ipc {

namespace {

std::array<unsigned char, 4> encode_length(std::size_t n) {
    return {static_cast<unsigned char>(n & 0xFF), static_cast<unsigned char>((n >> 8) & 0xFF),
            static_cast<unsigned char>((n >> 16) & 0xFF), static_cast<unsigned char>((n >> 24) & 0xFF)};
}

std::size_t decode_length(const std::array<unsigned char, 4>& b) {
    return static_cast<std::size_t>(b[0]) | (static_cast<std::size_t>(b[1]) << 8) |
           (static_cast<std::size_t>(b[2]) << 16) | (static_cast<std::size_t>(b[3]) << 24);
}

} // namespace

#ifdef _WIN32

// ===========================================================================
// Windows: named pipes with overlapped I/O, so close() can interrupt a
// blocked read, write or accept from another thread.
// ===========================================================================

namespace {

struct handle_closer {
    void operator()(HANDLE h) const {
        if (h && h != INVALID_HANDLE_VALUE) ::CloseHandle(h);
    }
};
using unique_handle = std::unique_ptr<void, handle_closer>;

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    const int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring out(static_cast<std::size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

// The current user's SID (from the process token), or an empty buffer.
std::unique_ptr<unsigned char[]> current_user_sid() {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) return nullptr;
    unique_handle guard(token);
    DWORD size = 0;
    ::GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    if (size == 0) return nullptr;
    auto buffer = std::make_unique<unsigned char[]>(size);
    if (!::GetTokenInformation(token, TokenUser, buffer.get(), size, &size)) return nullptr;
    const auto* user = reinterpret_cast<TOKEN_USER*>(buffer.get());
    const DWORD sid_size = ::GetLengthSid(user->User.Sid);
    auto sid = std::make_unique<unsigned char[]>(sid_size);
    if (!::CopySid(sid_size, sid.get(), user->User.Sid)) return nullptr;
    return sid;
}

std::wstring sid_string(PSID sid) {
    LPWSTR text = nullptr;
    if (!sid || !::ConvertSidToStringSidW(sid, &text)) return {};
    std::wstring out(text);
    ::LocalFree(text);
    return out;
}

// Runs one overlapped read or write; waits for it or for `cancel`.
bool overlapped_io(HANDLE h, HANDLE cancel, bool write, void* buffer, DWORD size, DWORD& done) {
    done = 0;
    unique_handle event(::CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!event) return false;
    OVERLAPPED ov{};
    ov.hEvent = event.get();
    const BOOL started = write ? ::WriteFile(h, buffer, size, nullptr, &ov)
                               : ::ReadFile(h, buffer, size, nullptr, &ov);
    if (!started && ::GetLastError() != ERROR_IO_PENDING) return false;
    HANDLE waits[2] = {event.get(), cancel};
    if (::WaitForMultipleObjects(2, waits, FALSE, INFINITE) != WAIT_OBJECT_0) {
        ::CancelIoEx(h, &ov);
        ::GetOverlappedResult(h, &ov, &done, TRUE); // the buffer must outlive the I/O
        return false;
    }
    return ::GetOverlappedResult(h, &ov, &done, FALSE) && done > 0;
}

} // namespace

struct connection::impl {
    unique_handle pipe;
    unique_handle cancel{::CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    bool server = false;
    std::mutex write_mutex;

    bool read_exact(void* out, std::size_t size) {
        auto* p = static_cast<unsigned char*>(out);
        while (size > 0) {
            DWORD done = 0;
            const DWORD chunk = static_cast<DWORD>(size > 65536 ? 65536 : size);
            if (!overlapped_io(pipe.get(), cancel.get(), false, p, chunk, done)) return false;
            p += done;
            size -= done;
        }
        return true;
    }

    bool write_all(const void* data, std::size_t size) {
        const auto* p = static_cast<const unsigned char*>(data);
        while (size > 0) {
            DWORD done = 0;
            const DWORD chunk = static_cast<DWORD>(size > 65536 ? 65536 : size);
            if (!overlapped_io(pipe.get(), cancel.get(), true, const_cast<unsigned char*>(p), chunk, done)) {
                return false;
            }
            p += done;
            size -= done;
        }
        return true;
    }

    ~impl() {
        if (server && pipe) {
            ::FlushFileBuffers(pipe.get());
            ::DisconnectNamedPipe(pipe.get());
        }
    }
};

std::string default_endpoint() {
    const auto sid = current_user_sid();
    DWORD session = 0;
    ::ProcessIdToSessionId(::GetCurrentProcessId(), &session);
    const std::wstring wsid = sid_string(sid.get());
    std::string name = "\\\\.\\pipe\\phylaxbox.browser.";
    for (wchar_t c : wsid) name.push_back(static_cast<char>(c)); // SIDs are ASCII
    name += "." + std::to_string(session);
    return name;
}

std::optional<connection> connection::connect(const std::string& endpoint) {
    const std::wstring name = widen(endpoint);
    HANDLE h = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 3; ++attempt) {
        // SECURITY_IDENTIFICATION: the server may identify us, not act as us.
        h = ::CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                          FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
        if (h != INVALID_HANDLE_VALUE) break;
        if (::GetLastError() != ERROR_PIPE_BUSY || !::WaitNamedPipeW(name.c_str(), 2000)) return std::nullopt;
    }
    if (h == INVALID_HANDLE_VALUE) return std::nullopt;
    unique_handle pipe(h);

    // Refuse a pipe created by another user (a squatter holding the name).
    PSID owner = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (::GetSecurityInfo(pipe.get(), SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION, &owner, nullptr,
                          nullptr, nullptr, &sd) != ERROR_SUCCESS) {
        return std::nullopt;
    }
    const auto me = current_user_sid();
    const bool same_user = me && owner && ::EqualSid(owner, me.get());
    ::LocalFree(sd);
    if (!same_user) return std::nullopt;

    auto p = std::make_unique<impl>();
    p->pipe = std::move(pipe);
    if (!p->cancel) return std::nullopt;
    return connection(std::move(p));
}

namespace {

class pipe_listener final : public listener {
public:
    explicit pipe_listener(std::wstring name) : m_name(std::move(name)) {}

    bool start() {
        const auto sid = current_user_sid();
        const std::wstring user = sid_string(sid.get());
        if (user.empty() || !m_stop) return false;
        // Owner and only grantee: the current user. "P": no inherited ACEs.
        const std::wstring sddl = L"O:" + user + L"D:P(A;;GA;;;" + user + L")";
        PSECURITY_DESCRIPTOR sd = nullptr;
        if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd,
                                                                    nullptr)) {
            return false;
        }
        m_sd.reset(sd);
        m_next = create_instance(true);
        return static_cast<bool>(m_next);
    }

    std::optional<connection> accept() override {
        std::unique_lock<std::mutex> lock(m_mutex);
        if (m_closed) return std::nullopt;
        if (!m_next) m_next = create_instance(false);
        if (!m_next) return std::nullopt;
        HANDLE instance = m_next.get();
        lock.unlock();

        unique_handle event(::CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!event) return std::nullopt;
        OVERLAPPED ov{};
        ov.hEvent = event.get();
        bool connected = false;
        if (::ConnectNamedPipe(instance, &ov)) {
            connected = true;
        } else {
            const DWORD err = ::GetLastError();
            if (err == ERROR_PIPE_CONNECTED) {
                connected = true;
            } else if (err == ERROR_IO_PENDING) {
                HANDLE waits[2] = {event.get(), m_stop.get()};
                if (::WaitForMultipleObjects(2, waits, FALSE, INFINITE) == WAIT_OBJECT_0) {
                    DWORD ignored = 0;
                    connected = ::GetOverlappedResult(instance, &ov, &ignored, FALSE) != FALSE;
                } else {
                    ::CancelIoEx(instance, &ov);
                    DWORD ignored = 0;
                    ::GetOverlappedResult(instance, &ov, &ignored, TRUE);
                }
            }
        }

        lock.lock();
        if (!connected || m_closed) {
            if (!m_closed) m_next.reset(); // broken instance: make a new one next time
            return std::nullopt;
        }
        auto p = std::make_unique<connection::impl>();
        p->pipe = std::move(m_next);
        p->server = true;
        // Keep holding the name: the next instance exists before we return.
        m_next = create_instance(false);
        if (!p->cancel) return std::nullopt;
        return connection(std::move(p));
    }

    void close() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_closed = true;
        ::SetEvent(m_stop.get());
    }

    ~pipe_listener() override {
        close();
        std::lock_guard<std::mutex> lock(m_mutex);
        m_next.reset();
    }

private:
    unique_handle create_instance(bool first) {
        SECURITY_ATTRIBUTES sa{sizeof(sa), m_sd.get(), FALSE};
        DWORD open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
        if (first) open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        HANDLE h = ::CreateNamedPipeW(m_name.c_str(), open_mode,
                                      PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                                      PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, &sa);
        if (h == INVALID_HANDLE_VALUE) return nullptr;
        return unique_handle(h);
    }

    struct local_free {
        void operator()(void* p) const { ::LocalFree(p); }
    };

    std::wstring m_name;
    std::unique_ptr<void, local_free> m_sd;
    unique_handle m_stop{::CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    std::mutex m_mutex;
    unique_handle m_next;
    bool m_closed = false;
};

} // namespace

std::unique_ptr<listener> listener::create(const std::string& endpoint) {
    auto l = std::make_unique<pipe_listener>(widen(endpoint));
    if (!l->start()) return nullptr;
    return l;
}

void connection::close() {
    if (m_impl && m_impl->cancel) ::SetEvent(m_impl->cancel.get());
}

#else

// ===========================================================================
// POSIX: Unix domain sockets. shutdown() interrupts blocked calls; the
// descriptor itself is only closed by the destructor.
// ===========================================================================

namespace {

bool peer_is_same_user(int fd) {
#ifdef __linux__
    struct ucred cred {};
    socklen_t len = sizeof(cred);
    if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) return false;
    return cred.uid == ::geteuid();
#else
    uid_t uid = 0;
    gid_t gid = 0;
    if (::getpeereid(fd, &uid, &gid) != 0) return false;
    return uid == ::geteuid();
#endif
}

// A directory we own, not a symlink, with no access for others.
bool private_directory(const std::string& dir) {
    struct stat st {};
    if (::lstat(dir.c_str(), &st) != 0) return false;
    return S_ISDIR(st.st_mode) && st.st_uid == ::geteuid() && (st.st_mode & 077) == 0;
}

bool make_address(const std::string& path, sockaddr_un& addr) {
    std::memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (path.size() >= sizeof(addr.sun_path)) return false;
    std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);
    return true;
}

int connect_socket(const std::string& path) {
    sockaddr_un addr{};
    if (!make_address(path, addr)) return -1;
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

std::string parent_dir(const std::string& path) {
    const auto slash = path.rfind('/');
    return slash == std::string::npos ? std::string(".") : path.substr(0, slash);
}

} // namespace

struct connection::impl {
    int fd = -1;
    std::atomic<bool> closed{false};
    std::mutex write_mutex;

    bool read_exact(void* out, std::size_t size) {
        auto* p = static_cast<unsigned char*>(out);
        while (size > 0) {
            const ssize_t n = ::recv(fd, p, size, 0);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0 || closed) return false;
            p += n;
            size -= static_cast<std::size_t>(n);
        }
        return true;
    }

    bool write_all(const void* data, std::size_t size) {
        const auto* p = static_cast<const unsigned char*>(data);
        while (size > 0) {
            const ssize_t n = ::send(fd, p, size, MSG_NOSIGNAL);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0 || closed) return false;
            p += n;
            size -= static_cast<std::size_t>(n);
        }
        return true;
    }

    ~impl() {
        if (fd >= 0) ::close(fd);
    }
};

std::string default_endpoint() {
    if (const char* runtime = std::getenv("XDG_RUNTIME_DIR"); runtime && *runtime && private_directory(runtime)) {
        return std::string(runtime) + "/phylaxbox-browser.sock";
    }
    return "/tmp/phylaxbox-" + std::to_string(::geteuid()) + "/browser.sock";
}

std::optional<connection> connection::connect(const std::string& endpoint) {
    if (!private_directory(parent_dir(endpoint))) return std::nullopt;
    const int fd = connect_socket(endpoint);
    if (fd < 0) return std::nullopt;
    auto p = std::make_unique<impl>();
    p->fd = fd;
    if (!peer_is_same_user(fd)) return std::nullopt;
    return connection(std::move(p));
}

namespace {

class socket_listener final : public listener {
public:
    explicit socket_listener(std::string path) : m_path(std::move(path)) {}

    bool start() {
        const std::string dir = parent_dir(m_path);
        if (!private_directory(dir)) {
            // Our own fallback directory in /tmp: create it, then check it.
            ::mkdir(dir.c_str(), 0700);
            if (!private_directory(dir)) return false;
        }
        // Someone answers: another instance is running. Otherwise a stale
        // socket file is left from a crash and can go.
        if (const int probe = connect_socket(m_path); probe >= 0) {
            ::close(probe);
            return false;
        }
        ::unlink(m_path.c_str());

        sockaddr_un addr{};
        if (!make_address(m_path, addr)) return false;
        m_fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (m_fd < 0) return false;
        if (::bind(m_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
            ::chmod(m_path.c_str(), 0600) != 0 || ::listen(m_fd, 8) != 0) {
            return false;
        }
        m_bound = true;
        return true;
    }

    std::optional<connection> accept() override {
        for (;;) {
            if (m_closed) return std::nullopt;
            const int fd = ::accept4(m_fd, nullptr, nullptr, SOCK_CLOEXEC);
            if (fd < 0) {
                if (errno == EINTR || errno == ECONNABORTED) continue;
                return std::nullopt;
            }
            auto p = std::make_unique<connection::impl>();
            p->fd = fd;
            if (m_closed) return std::nullopt;
            if (!peer_is_same_user(fd)) continue; // dropped by p's destructor
            return connection(std::move(p));
        }
    }

    void close() override {
        if (m_closed.exchange(true)) return;
        if (m_fd >= 0) ::shutdown(m_fd, SHUT_RDWR);
    }

    ~socket_listener() override {
        close();
        if (m_fd >= 0) ::close(m_fd);
        if (m_bound) ::unlink(m_path.c_str());
    }

private:
    std::string m_path;
    int m_fd = -1;
    bool m_bound = false;
    std::atomic<bool> m_closed{false};
};

} // namespace

std::unique_ptr<listener> listener::create(const std::string& endpoint) {
    auto l = std::make_unique<socket_listener>(endpoint);
    if (!l->start()) return nullptr;
    return l;
}

void connection::close() {
    if (!m_impl || m_impl->closed.exchange(true)) return;
    ::shutdown(m_impl->fd, SHUT_RDWR);
}

#endif

// ===========================================================================
// Framing (both platforms)
// ===========================================================================

connection::connection(std::unique_ptr<impl> p) : m_impl(std::move(p)) {}
connection::connection(connection&& other) noexcept = default;
connection& connection::operator=(connection&& other) noexcept = default;
connection::~connection() = default;

std::optional<std::string> connection::read(std::size_t max) {
    if (!m_impl) return std::nullopt;
    std::array<unsigned char, 4> header{};
    if (!m_impl->read_exact(header.data(), header.size())) return std::nullopt;
    const std::size_t size = decode_length(header);
    if (size > max || size > MAX_MESSAGE) return std::nullopt;
    std::string payload(size, '\0');
    if (size > 0 && !m_impl->read_exact(payload.data(), size)) return std::nullopt;
    return payload;
}

bool connection::write(std::string_view payload) {
    if (!m_impl || payload.size() > MAX_MESSAGE) return false;
    std::lock_guard<std::mutex> lock(m_impl->write_mutex);
    const auto header = encode_length(payload.size());
    return m_impl->write_all(header.data(), header.size()) &&
           (payload.empty() || m_impl->write_all(payload.data(), payload.size()));
}

} // namespace pb::ipc
