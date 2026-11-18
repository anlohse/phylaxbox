// Real system clipboard checks. They replace the clipboard content, so they
// are disabled by default and restore the previous text when they finish.
// Run with:
//   phylaxbox_desktop_tests --gtest_also_run_disabled_tests --gtest_filter=*RealClipboard*
#include <gtest/gtest.h>

#include "secret_clipboard.h"

#include <cstring>
#include <optional>
#include <string>

#ifdef _WIN32
#include <windows.h>

namespace {

std::optional<std::wstring> read_text() {
    if (!OpenClipboard(nullptr)) return std::nullopt;
    std::optional<std::wstring> out;
    if (HANDLE h = GetClipboardData(CF_UNICODETEXT)) {
        if (const auto* p = static_cast<const wchar_t*>(GlobalLock(h))) {
            out = std::wstring(p);
            GlobalUnlock(h);
        }
    }
    CloseClipboard();
    return out;
}

void write_text(const std::wstring& text) {
    if (!OpenClipboard(nullptr)) return;
    EmptyClipboard();
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, (text.size() + 1) * sizeof(wchar_t));
    std::memcpy(GlobalLock(h), text.c_str(), (text.size() + 1) * sizeof(wchar_t));
    GlobalUnlock(h);
    SetClipboardData(CF_UNICODETEXT, h);
    CloseClipboard();
}

bool has_format(const wchar_t* name) {
    return IsClipboardFormatAvailable(RegisterClipboardFormatW(name)) != FALSE;
}

// Saves the user's clipboard text and puts it back afterwards.
struct restore_clipboard {
    std::optional<std::wstring> saved = read_text();
    ~restore_clipboard() {
        if (saved) write_text(*saved);
    }
};

} // namespace

TEST(SecretClipboard, DISABLED_RealClipboardCopyHideAndClear) {
    restore_clipboard guard;
    pb::app::secret_clipboard clipboard;

    ASSERT_TRUE(clipboard.copy("s\xC3\xA9nha-123")); // UTF-8 in, UTF-16 on the clipboard
    EXPECT_EQ(read_text(), std::wstring(L"sénha-123"));
    EXPECT_TRUE(has_format(L"CanIncludeInClipboardHistory"));
    EXPECT_TRUE(has_format(L"CanUploadToCloudClipboard"));
    EXPECT_TRUE(has_format(L"ExcludeClipboardContentFromMonitorProcessing"));

    clipboard.clear_if_ours();
    EXPECT_FALSE(read_text().has_value());
}

TEST(SecretClipboard, DISABLED_RealClipboardNeverClearsWhatTheUserCopiedLater) {
    restore_clipboard guard;
    pb::app::secret_clipboard clipboard;

    ASSERT_TRUE(clipboard.copy("secret"));
    write_text(L"something the user copied afterwards");
    clipboard.clear_if_ours();
    EXPECT_EQ(read_text(), std::wstring(L"something the user copied afterwards"));
}

#endif // _WIN32
