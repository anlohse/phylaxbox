#ifndef PB_IPC_LOCAL_CHANNEL_H_
#define PB_IPC_LOCAL_CHANNEL_H_

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

// Local channel between the native messaging host and the desktop app
// (spec §9.3): a named pipe on Windows, a Unix domain socket elsewhere.
// Messages are framed as a 4-byte little-endian length and the payload.
//
// Access control comes from the operating system (spec §8.4):
//   Windows: the pipe name includes the user SID and session id; its DACL
//            grants access to the current user only, remote clients are
//            rejected, and the first instance is created with
//            FILE_FLAG_FIRST_PIPE_INSTANCE so the app notices if another
//            process already holds the name. Clients check that the pipe is
//            owned by their own user before talking to it.
//   Linux:   the socket lives in $XDG_RUNTIME_DIR (or a 0700 directory in
//            /tmp checked for ownership), and both ends check the peer's
//            user id (SO_PEERCRED).
// Authentication of the browser extension itself happens above this layer
// (pairing keys, see docs/browser-integration/protocol.md).
namespace pb::ipc {

// Largest message either side accepts (Chrome limits host -> browser
// messages to 1 MiB).
constexpr std::size_t MAX_MESSAGE = 1024 * 1024;

// The endpoint for the current user (and, on Windows, logon session).
std::string default_endpoint();

class connection {
public:
    connection(connection&& other) noexcept;
    connection& operator=(connection&& other) noexcept;
    connection(const connection&) = delete;
    connection& operator=(const connection&) = delete;
    ~connection();

    // Connects to a listening endpoint. nullopt if nothing listens there, or
    // if the other end does not belong to the current user.
    static std::optional<connection> connect(const std::string& endpoint);

    // Blocks for one message. nullopt when the peer closed the channel, on
    // errors, after close(), or when the message is larger than `max`.
    std::optional<std::string> read(std::size_t max = MAX_MESSAGE);
    // False when the channel is closed or broken, or the payload too large.
    bool write(std::string_view payload);

    // Unblocks pending reads and writes (from any thread); later calls fail.
    void close();

    struct impl;
    explicit connection(std::unique_ptr<impl> p);

private:
    std::unique_ptr<impl> m_impl;
};

class listener {
public:
    // nullptr when the endpoint cannot be created, e.g. because another
    // instance of the app is listening there.
    static std::unique_ptr<listener> create(const std::string& endpoint);

    virtual ~listener() = default;

    // Blocks until a client of the same user connects. nullopt after close().
    virtual std::optional<connection> accept() = 0;
    // Unblocks accept() (from any thread) and stops listening.
    virtual void close() = 0;
};

} // namespace pb::ipc

#endif // PB_IPC_LOCAL_CHANNEL_H_
