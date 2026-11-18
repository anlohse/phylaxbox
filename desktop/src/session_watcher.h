#ifndef PB_SESSION_WATCHER_H_
#define PB_SESSION_WATCHER_H_

#include <functional>
#include <memory>

namespace pb::app {

// Reports desktop events that should lock the vault (spec §7.5). Callbacks
// run on the UI thread.
//  * Windows: session lock (WTS notifications) and minimize (WM_SIZE), by
//    subclassing the webview's top-level window.
//  * Linux: minimize (GTK window-state-event); session lock through D-Bus
//    (logind Session.Lock, and the GNOME / freedesktop screensaver
//    ActiveChanged signal).
class session_watcher {
public:
    struct callbacks {
        std::function<void()> on_session_locked;
        std::function<void()> on_minimized;
    };

    // `native_window`: HWND on Windows, GtkWindow* on Linux. Call on the UI thread.
    session_watcher(void* native_window, callbacks cb);
    ~session_watcher();
    session_watcher(const session_watcher&) = delete;
    session_watcher& operator=(const session_watcher&) = delete;

private:
    struct state;
    std::unique_ptr<state> m;
};

} // namespace pb::app

#endif // PB_SESSION_WATCHER_H_
