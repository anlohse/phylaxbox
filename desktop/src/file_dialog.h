#ifndef PB_FILE_DIALOG_H_
#define PB_FILE_DIALOG_H_

#include <optional>
#include <string>

namespace pb::app {

struct file_dialog_request {
    bool save = false;           // false: open an existing vault; true: choose where to create one
    std::string title;           // UTF-8, already translated by the UI
    std::string filter_name;     // e.g. "PhylaxBox vault"
    std::string suggested_name;  // save dialogs: default file name
};

// Native file dialog filtered to *.phylaxbox. Call on the UI thread.
// `native_window`: HWND on Windows, GtkWindow* on Linux (dialog parent).
// Returns the chosen path as UTF-8, or nullopt when cancelled.
std::optional<std::string> choose_vault_file(void* native_window, const file_dialog_request& request);

} // namespace pb::app

#endif // PB_FILE_DIALOG_H_
