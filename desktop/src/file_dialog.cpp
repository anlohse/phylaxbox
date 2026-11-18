#include "file_dialog.h"

#ifdef _WIN32
#include <windows.h>
#include <shobjidl.h>
#else
#include <gtk/gtk.h>
#endif

namespace pb::app {

#ifdef _WIN32

namespace {

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring out(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

std::string narrow(const wchar_t* s) {
    const int n = WideCharToMultiByte(CP_UTF8, 0, s, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string out(static_cast<std::size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, s, -1, out.data(), n, nullptr, nullptr);
    return out;
}

template <typename T>
struct com_ptr {
    T* p = nullptr;
    ~com_ptr() {
        if (p) p->Release();
    }
    T** operator&() { return &p; }
    T* operator->() const { return p; }
};

} // namespace

std::optional<std::string> choose_vault_file(void* native_window, const file_dialog_request& r) {
    // The UI thread already runs COM (WebView2); this is a no-op there.
    const HRESULT init = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    const bool uninit = SUCCEEDED(init);

    std::optional<std::string> result;
    com_ptr<IFileDialog> dialog;
    const HRESULT created =
        r.save ? CoCreateInstance(CLSID_FileSaveDialog, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_PPV_ARGS(reinterpret_cast<IFileSaveDialog**>(&dialog)))
               : CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_PPV_ARGS(reinterpret_cast<IFileOpenDialog**>(&dialog)));
    if (SUCCEEDED(created)) {
        const std::wstring filter_name = widen(r.filter_name.empty() ? "PhylaxBox" : r.filter_name);
        const COMDLG_FILTERSPEC filters[] = {{filter_name.c_str(), L"*.phylaxbox"}};
        dialog->SetFileTypes(1, filters);
        dialog->SetDefaultExtension(L"phylaxbox");
        if (!r.title.empty()) dialog->SetTitle(widen(r.title).c_str());
        if (r.save && !r.suggested_name.empty()) dialog->SetFileName(widen(r.suggested_name).c_str());
        FILEOPENDIALOGOPTIONS options = 0;
        dialog->GetOptions(&options);
        options |= FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST;
        options |= r.save ? FOS_OVERWRITEPROMPT : FOS_FILEMUSTEXIST;
        dialog->SetOptions(options);

        if (SUCCEEDED(dialog->Show(static_cast<HWND>(native_window)))) {
            com_ptr<IShellItem> item;
            if (SUCCEEDED(dialog->GetResult(&item))) {
                PWSTR path = nullptr;
                if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path)) && path) {
                    result = narrow(path);
                    CoTaskMemFree(path);
                }
            }
        }
    }
    if (uninit) CoUninitialize();
    return result;
}

#else // GTK 3

std::optional<std::string> choose_vault_file(void* native_window, const file_dialog_request& r) {
    GtkFileChooserNative* dialog = gtk_file_chooser_native_new(
        r.title.c_str(), GTK_WINDOW(native_window),
        r.save ? GTK_FILE_CHOOSER_ACTION_SAVE : GTK_FILE_CHOOSER_ACTION_OPEN, nullptr, nullptr);
    GtkFileChooser* chooser = GTK_FILE_CHOOSER(dialog);
    GtkFileFilter* filter = gtk_file_filter_new();
    gtk_file_filter_set_name(filter, r.filter_name.empty() ? "PhylaxBox" : r.filter_name.c_str());
    gtk_file_filter_add_pattern(filter, "*.phylaxbox");
    gtk_file_chooser_add_filter(chooser, filter); // takes ownership
    if (r.save) {
        gtk_file_chooser_set_do_overwrite_confirmation(chooser, TRUE);
        if (!r.suggested_name.empty()) gtk_file_chooser_set_current_name(chooser, r.suggested_name.c_str());
    }

    std::optional<std::string> result;
    if (gtk_native_dialog_run(GTK_NATIVE_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        if (gchar* filename = gtk_file_chooser_get_filename(chooser)) {
            if (gchar* utf8 = g_filename_to_utf8(filename, -1, nullptr, nullptr, nullptr)) {
                result = std::string(utf8);
                const std::string ext = ".phylaxbox";
                const bool has_ext = result->size() >= ext.size() &&
                                     result->compare(result->size() - ext.size(), ext.size(), ext) == 0;
                if (r.save && !has_ext) *result += ext; // GTK does not add it
                g_free(utf8);
            }
            g_free(filename);
        }
    }
    g_object_unref(dialog);
    return result;
}

#endif

} // namespace pb::app
