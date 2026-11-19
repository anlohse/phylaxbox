// PhylaxBox native messaging host: started by the browser for the PhylaxBox
// extension, it relays messages between the browser (stdin/stdout, native
// messaging framing) and the desktop app (local IPC). See relay.h.
#include "relay.h"

#include <sodium.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>

#ifdef _WIN32
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#else
#include <climits>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {

// Native messaging framing: a 32-bit length in native byte order, then UTF-8 JSON.
std::optional<std::string> read_message() {
    std::uint32_t length = 0;
    if (std::fread(&length, sizeof(length), 1, stdin) != 1) return std::nullopt;
    // Larger than any valid request: stop instead of reading it (the browser
    // then closes the extension's port).
    if (length > pb::host::MAX_BROWSER_MESSAGE) return std::nullopt;
    std::string message(length, '\0');
    if (length > 0 && std::fread(message.data(), 1, length, stdin) != length) return std::nullopt;
    return message;
}

bool write_message(const std::string& message) {
    const auto length = static_cast<std::uint32_t>(message.size());
    return std::fwrite(&length, sizeof(length), 1, stdout) == 1 &&
           std::fwrite(message.data(), 1, message.size(), stdout) == message.size() && std::fflush(stdout) == 0;
}

// Starts the desktop app installed next to this executable (fixed path, no
// arguments: nothing from the browser reaches the command line).
bool launch_app() {
#ifdef _WIN32
    std::wstring path(32768, L'\0');
    const DWORD n = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (n == 0 || n >= path.size()) return false;
    path.resize(n);
    const auto slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return false;
    const std::wstring dir = path.substr(0, slash);
    const std::wstring exe = dir + L"\\PhylaxBox.exe";
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    // Browsers run native hosts in a job object; leave it so the app keeps
    // running after the host exits (fall back if breakaway is not allowed).
    BOOL ok = CreateProcessW(exe.c_str(), nullptr, nullptr, nullptr, FALSE,
                             CREATE_BREAKAWAY_FROM_JOB | CREATE_NEW_PROCESS_GROUP, nullptr, dir.c_str(), &si, &pi);
    if (!ok) {
        ok = CreateProcessW(exe.c_str(), nullptr, nullptr, nullptr, FALSE, CREATE_NEW_PROCESS_GROUP, nullptr,
                            dir.c_str(), &si, &pi);
    }
    if (!ok) return false;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
#else
    char self[PATH_MAX];
    const ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (n <= 0) return false;
    self[n] = '\0';
    std::string exe(self);
    const auto slash = exe.rfind('/');
    if (slash == std::string::npos) return false;
    exe = exe.substr(0, slash) + "/phylaxbox";
    if (access(exe.c_str(), X_OK) != 0) return false;

    const pid_t child = fork();
    if (child < 0) return false;
    if (child == 0) {
        // Detach: new session, and a grandchild so no zombie is left behind.
        setsid();
        if (fork() != 0) _exit(0);
        // Never hand the browser's pipes to the app.
        const int null_fd = open("/dev/null", O_RDWR);
        if (null_fd >= 0) {
            dup2(null_fd, 0);
            dup2(null_fd, 1);
            dup2(null_fd, 2);
            if (null_fd > 2) close(null_fd);
        }
        execl(exe.c_str(), exe.c_str(), static_cast<char*>(nullptr));
        _exit(127);
    }
    int status = 0;
    waitpid(child, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
#endif
}

} // namespace

int main(int argc, char** argv) {
#ifdef _WIN32
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    if (sodium_init() < 0) return 1;
    pb::host::relay relay(pb::host::relay::origin_from_args(argc, argv), pb::ipc::default_endpoint(), launch_app);
    return relay.run({read_message, write_message});
}
