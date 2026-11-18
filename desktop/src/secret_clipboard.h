#ifndef PB_SECRET_CLIPBOARD_H_
#define PB_SECRET_CLIPBOARD_H_

#include <memory>
#include <string_view>

namespace pb::app {

// System clipboard for credentials (spec §12.3). Call on the UI thread.
//  * Windows: the content is flagged so it stays out of clipboard history
//    and cloud clipboard and is skipped by clipboard monitors.
//  * Linux (GTK 3): offers the KDE "x-kde-passwordManagerHint: secret"
//    target so clipboard managers that honour it do not record it.
// clear_if_ours() only clears when the clipboard still holds what copy()
// put there, never content the user copied afterwards.
class secret_clipboard {
public:
    secret_clipboard();
    ~secret_clipboard();
    secret_clipboard(const secret_clipboard&) = delete;
    secret_clipboard& operator=(const secret_clipboard&) = delete;

    bool copy(std::string_view utf8);
    void clear_if_ours();

private:
    struct state;
    std::unique_ptr<state> m;
};

} // namespace pb::app

#endif // PB_SECRET_CLIPBOARD_H_
