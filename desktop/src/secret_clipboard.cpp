#include "secret_clipboard.h"

#include <sodium.h>

#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <gtk/gtk.h>
#endif

namespace pb::app {

#ifdef _WIN32

struct secret_clipboard::state {
    DWORD sequence = 0; // GetClipboardSequenceNumber() right after our copy
    bool owned = false;
};

namespace {

// Opens the clipboard, retrying briefly: another process may hold it.
bool open_clipboard() {
    for (int i = 0; i < 10; ++i) {
        if (OpenClipboard(nullptr)) return true;
        Sleep(10);
    }
    return false;
}

bool set_dword_format(const wchar_t* name, DWORD value) {
    const UINT format = RegisterClipboardFormatW(name);
    if (!format) return false;
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, sizeof(DWORD));
    if (!h) return false;
    *static_cast<DWORD*>(GlobalLock(h)) = value;
    GlobalUnlock(h);
    if (!SetClipboardData(format, h)) {
        GlobalFree(h);
        return false;
    }
    return true;
}

} // namespace

secret_clipboard::secret_clipboard() : m(std::make_unique<state>()) {}
secret_clipboard::~secret_clipboard() = default;

bool secret_clipboard::copy(std::string_view utf8) {
    const int wide_len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(),
                                             static_cast<int>(utf8.size()), nullptr, 0);
    if (wide_len < 0 || (wide_len == 0 && !utf8.empty())) return false;

    const SIZE_T bytes = (static_cast<SIZE_T>(wide_len) + 1) * sizeof(wchar_t);
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!h) return false;
    auto* wide = static_cast<wchar_t*>(GlobalLock(h));
    MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), wide, wide_len);
    wide[wide_len] = L'\0';
    GlobalUnlock(h);

    if (!open_clipboard()) {
        sodium_memzero(GlobalLock(h), bytes);
        GlobalUnlock(h);
        GlobalFree(h);
        return false;
    }
    EmptyClipboard();
    const bool ok = SetClipboardData(CF_UNICODETEXT, h) != nullptr;
    if (!ok) GlobalFree(h);
    // Keep it out of Win+V history, cloud clipboard and clipboard monitors.
    set_dword_format(L"CanIncludeInClipboardHistory", 0);
    set_dword_format(L"CanUploadToCloudClipboard", 0);
    if (const UINT exclude = RegisterClipboardFormatW(L"ExcludeClipboardContentFromMonitorProcessing")) {
        SetClipboardData(exclude, GlobalAlloc(GMEM_MOVEABLE, 1));
    }
    CloseClipboard();

    m->sequence = GetClipboardSequenceNumber();
    m->owned = ok;
    return ok;
}

void secret_clipboard::clear_if_ours() {
    if (!m->owned) return;
    m->owned = false;
    if (GetClipboardSequenceNumber() != m->sequence) return; // replaced since
    if (open_clipboard()) {
        EmptyClipboard();
        CloseClipboard();
    }
}

#else // GTK 3

struct secret_clipboard::state {
    bool owned = false;
};

namespace {

struct payload {
    std::string text; // wiped in clear_payload
    secret_clipboard* owner;
    bool* owned_flag;
};

enum target_id : guint { TARGET_TEXT = 1, TARGET_HINT = 2 };

void get_payload(GtkClipboard*, GtkSelectionData* data, guint info, gpointer user) {
    auto* p = static_cast<payload*>(user);
    if (info == TARGET_HINT) {
        static const char secret[] = "secret";
        gtk_selection_data_set(data, gtk_selection_data_get_target(data), 8,
                               reinterpret_cast<const guchar*>(secret), sizeof(secret) - 1);
    } else {
        gtk_selection_data_set_text(data, p->text.c_str(), static_cast<gint>(p->text.size()));
    }
}

// Called by GTK when we clear it or when another application takes over.
void clear_payload(GtkClipboard*, gpointer user) {
    auto* p = static_cast<payload*>(user);
    *p->owned_flag = false;
    if (!p->text.empty()) sodium_memzero(p->text.data(), p->text.size());
    delete p;
}

} // namespace

secret_clipboard::secret_clipboard() : m(std::make_unique<state>()) {}
secret_clipboard::~secret_clipboard() = default;

bool secret_clipboard::copy(std::string_view utf8) {
    GtkClipboard* clipboard = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    if (!clipboard) return false;
    static const GtkTargetEntry targets[] = {
        {const_cast<gchar*>("UTF8_STRING"), 0, TARGET_TEXT},
        {const_cast<gchar*>("text/plain;charset=utf-8"), 0, TARGET_TEXT},
        {const_cast<gchar*>("TEXT"), 0, TARGET_TEXT},
        {const_cast<gchar*>("STRING"), 0, TARGET_TEXT},
        {const_cast<gchar*>("x-kde-passwordManagerHint"), 0, TARGET_HINT},
    };
    auto* p = new payload{std::string(utf8), this, &m->owned};
    if (!gtk_clipboard_set_with_data(clipboard, targets, G_N_ELEMENTS(targets), get_payload,
                                     clear_payload, p)) {
        clear_payload(clipboard, p);
        return false;
    }
    m->owned = true;
    return true;
}

void secret_clipboard::clear_if_ours() {
    if (!m->owned) return; // another application owns the clipboard now
    gtk_clipboard_clear(gtk_clipboard_get(GDK_SELECTION_CLIPBOARD)); // runs clear_payload
    m->owned = false;
}

#endif

} // namespace pb::app
