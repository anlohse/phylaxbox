#include "session_watcher.h"

#ifdef _WIN32
#include <windows.h>
#include <commctrl.h>
#include <wtsapi32.h>
#else
#include <gtk/gtk.h>
#endif

namespace pb::app {

#ifdef _WIN32

struct session_watcher::state {
    HWND hwnd = nullptr;
    callbacks cb;
    bool registered = false;
};

namespace {

constexpr UINT_PTR SUBCLASS_ID = 0x50425357; // "PBSW"

// `data` is the callbacks object owned by the watcher's state.
LRESULT CALLBACK watcher_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp, UINT_PTR, DWORD_PTR data) {
    auto* cb = reinterpret_cast<session_watcher::callbacks*>(data);
    if (msg == WM_WTSSESSION_CHANGE && wp == WTS_SESSION_LOCK) {
        if (cb->on_session_locked) cb->on_session_locked();
    } else if (msg == WM_SIZE && wp == SIZE_MINIMIZED) {
        if (cb->on_minimized) cb->on_minimized();
    }
    return DefSubclassProc(hwnd, msg, wp, lp);
}

} // namespace

session_watcher::session_watcher(void* native_window, callbacks cb) : m(std::make_unique<state>()) {
    m->hwnd = static_cast<HWND>(native_window);
    m->cb = std::move(cb);
    if (!m->hwnd) return;
    SetWindowSubclass(m->hwnd, watcher_proc, SUBCLASS_ID, reinterpret_cast<DWORD_PTR>(&m->cb));
    m->registered = WTSRegisterSessionNotification(m->hwnd, NOTIFY_FOR_THIS_SESSION) != FALSE;
}

session_watcher::~session_watcher() {
    if (!m->hwnd) return;
    if (m->registered) WTSUnRegisterSessionNotification(m->hwnd);
    RemoveWindowSubclass(m->hwnd, watcher_proc, SUBCLASS_ID);
}

#else // GTK 3 + GDBus

struct session_watcher::state {
    GtkWidget* window = nullptr;
    callbacks cb;
    gulong state_handler = 0;
    GDBusConnection* system_bus = nullptr;
    GDBusConnection* session_bus = nullptr;
    guint logind_sub = 0;
    guint gnome_sub = 0;
    guint freedesktop_sub = 0;
};

namespace {

gboolean on_window_state(GtkWidget*, GdkEventWindowState* event, gpointer user) {
    auto* st = static_cast<session_watcher::callbacks*>(user);
    if ((event->changed_mask & GDK_WINDOW_STATE_ICONIFIED) &&
        (event->new_window_state & GDK_WINDOW_STATE_ICONIFIED) && st->on_minimized) {
        st->on_minimized();
    }
    return FALSE;
}

void on_logind_lock(GDBusConnection*, const gchar*, const gchar*, const gchar*, const gchar*,
                    GVariant*, gpointer user) {
    auto* cb = static_cast<session_watcher::callbacks*>(user);
    if (cb->on_session_locked) cb->on_session_locked();
}

void on_screensaver(GDBusConnection*, const gchar*, const gchar*, const gchar*, const gchar*,
                    GVariant* params, gpointer user) {
    auto* cb = static_cast<session_watcher::callbacks*>(user);
    gboolean active = FALSE;
    if (g_variant_is_of_type(params, G_VARIANT_TYPE("(b)"))) g_variant_get(params, "(b)", &active);
    if (active && cb->on_session_locked) cb->on_session_locked();
}

} // namespace

session_watcher::session_watcher(void* native_window, callbacks cb) : m(std::make_unique<state>()) {
    m->window = static_cast<GtkWidget*>(native_window);
    m->cb = std::move(cb);
    if (m->window) {
        m->state_handler = g_signal_connect(m->window, "window-state-event",
                                            G_CALLBACK(on_window_state), &m->cb);
    }
    // Any logind session of this user; the signal is sent to the session object.
    m->system_bus = g_bus_get_sync(G_BUS_TYPE_SYSTEM, nullptr, nullptr);
    if (m->system_bus) {
        m->logind_sub = g_dbus_connection_signal_subscribe(
            m->system_bus, "org.freedesktop.login1", "org.freedesktop.login1.Session", "Lock",
            nullptr, nullptr, G_DBUS_SIGNAL_FLAGS_NONE, on_logind_lock, &m->cb, nullptr);
    }
    m->session_bus = g_bus_get_sync(G_BUS_TYPE_SESSION, nullptr, nullptr);
    if (m->session_bus) {
        m->gnome_sub = g_dbus_connection_signal_subscribe(
            m->session_bus, nullptr, "org.gnome.ScreenSaver", "ActiveChanged", nullptr, nullptr,
            G_DBUS_SIGNAL_FLAGS_NONE, on_screensaver, &m->cb, nullptr);
        m->freedesktop_sub = g_dbus_connection_signal_subscribe(
            m->session_bus, nullptr, "org.freedesktop.ScreenSaver", "ActiveChanged", nullptr,
            nullptr, G_DBUS_SIGNAL_FLAGS_NONE, on_screensaver, &m->cb, nullptr);
    }
}

session_watcher::~session_watcher() {
    if (m->window && m->state_handler) g_signal_handler_disconnect(m->window, m->state_handler);
    if (m->system_bus) {
        if (m->logind_sub) g_dbus_connection_signal_unsubscribe(m->system_bus, m->logind_sub);
        g_object_unref(m->system_bus);
    }
    if (m->session_bus) {
        if (m->gnome_sub) g_dbus_connection_signal_unsubscribe(m->session_bus, m->gnome_sub);
        if (m->freedesktop_sub) g_dbus_connection_signal_unsubscribe(m->session_bus, m->freedesktop_sub);
        g_object_unref(m->session_bus);
    }
}

#endif

} // namespace pb::app
