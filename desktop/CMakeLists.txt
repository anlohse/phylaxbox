include(GNUInstallDirs)

# PhylaxBox Desktop: webview UI, TLS transport, OAuth loopback, OS integration.
find_package(OpenSSL REQUIRED)
find_package(httplib CONFIG REQUIRED)

include(FetchContent)
FetchContent_Declare(
    webview
    GIT_REPOSITORY https://github.com/webview/webview
    GIT_TAG 0.12.0)
set(WEBVIEW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(WEBVIEW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(WEBVIEW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(WEBVIEW_BUILD_SHARED_LIBRARY OFF CACHE BOOL "" FORCE)
set(WEBVIEW_INSTALL_TARGETS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(webview)

# Base64 of a hex string (used for the CSP hashes below).
function(pb_hex_to_base64 hex out_var)
    set(alphabet "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
    string(LENGTH "${hex}" hex_len)
    set(result "")
    set(pos 0)
    while(pos LESS hex_len)
        set(group 0)
        set(count 0)
        foreach(i RANGE 0 2)
            math(EXPR group "${group} << 8")
            if(pos LESS hex_len)
                string(SUBSTRING "${hex}" ${pos} 2 byte)
                math(EXPR group "${group} | 0x${byte}")
                math(EXPR pos "${pos} + 2")
                math(EXPR count "${count} + 1")
            endif()
        endforeach()
        foreach(shift 18 12 6 0)
            math(EXPR index "(${group} >> ${shift}) & 63")
            string(SUBSTRING "${alphabet}" ${index} 1 char)
            string(APPEND result "${char}")
        endforeach()
        if(count EQUAL 1)
            string(REGEX REPLACE "..$" "==" result "${result}")
        elseif(count EQUAL 2)
            string(REGEX REPLACE ".$" "=" result "${result}")
        endif()
    endwhile()
    set(${out_var} "${result}" PARENT_SCOPE)
endfunction()

# SHA-256 (base64) of the text of the first <tag>...</tag> element of the page,
# as the browser computes it for a CSP 'sha256-...' source.
function(pb_inline_hash page tag out_var)
    string(FIND "${page}" "<${tag}>" begin)
    string(FIND "${page}" "</${tag}>" end)
    if(begin EQUAL -1 OR end EQUAL -1)
        message(FATAL_ERROR "frontend/app.html: no inline <${tag}> element")
    endif()
    string(LENGTH "<${tag}>" open_len)
    math(EXPR begin "${begin} + ${open_len}")
    math(EXPR len "${end} - ${begin}")
    string(SUBSTRING "${page}" ${begin} ${len} body)
    string(SHA256 hex "${body}")
    pb_hex_to_base64(${hex} b64)
    set(${out_var} "${b64}" PARENT_SCOPE)
endfunction()

# The UI page (frontend/app.html) is embedded in the binary as a byte array:
# no size limit on string literals and no escaping concerns. Its Content
# Security Policy allows only its own inline <script> and <style>, by hash,
# computed here so the page cannot drift from its policy.
set(PB_APP_PAGE ${CMAKE_CURRENT_SOURCE_DIR}/frontend/app.html)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${PB_APP_PAGE})
file(READ ${PB_APP_PAGE} PB_APP_PAGE_TEXT)
# HTML parsers turn CRLF into LF before hashing: do the same (git may check
# the file out with CRLF on Windows).
string(REPLACE "\r\n" "\n" PB_APP_PAGE_TEXT "${PB_APP_PAGE_TEXT}")
pb_inline_hash("${PB_APP_PAGE_TEXT}" script PB_SCRIPT_HASH)
pb_inline_hash("${PB_APP_PAGE_TEXT}" style PB_STYLE_HASH)
foreach(placeholder __PB_SCRIPT_HASH__ __PB_STYLE_HASH__)
    string(FIND "${PB_APP_PAGE_TEXT}" "${placeholder}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "frontend/app.html: CSP placeholder ${placeholder} is missing")
    endif()
endforeach()
string(REPLACE "__PB_SCRIPT_HASH__" "${PB_SCRIPT_HASH}" PB_APP_PAGE_TEXT "${PB_APP_PAGE_TEXT}")
string(REPLACE "__PB_STYLE_HASH__" "${PB_STYLE_HASH}" PB_APP_PAGE_TEXT "${PB_APP_PAGE_TEXT}")
set(PB_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
file(WRITE ${PB_GENERATED_DIR}/app.html "${PB_APP_PAGE_TEXT}")
file(READ ${PB_GENERATED_DIR}/app.html PB_APP_PAGE_HEX HEX)
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," PB_APP_PAGE_BYTES "${PB_APP_PAGE_HEX}")
string(REGEX REPLACE "((0x..,){16})" "\\1\n" PB_APP_PAGE_BYTES "${PB_APP_PAGE_BYTES}")
file(WRITE ${PB_GENERATED_DIR}/app_page.h.tmp
    "// Generated from desktop/frontend/app.html. Do not edit.\n"
    "#pragma once\n\n"
    "namespace pb::app {\n\n"
    "inline constexpr unsigned char APP_PAGE_HTML[] = {\n"
    "${PB_APP_PAGE_BYTES}"
    "};\n\n"
    "} // namespace pb::app\n")
configure_file(${PB_GENERATED_DIR}/app_page.h.tmp ${PB_GENERATED_DIR}/app_page.h COPYONLY)

# Everything but main(), so the desktop tests can link it.
add_library(phylaxbox_desktop_lib STATIC
    src/appui.cpp
    src/phylaxboxframework.cpp
    src/httplib_transport.cpp
    src/oauth_loopback.cpp
    src/dropbox_link.cpp
    src/vault_bridge.cpp
    src/secret_clipboard.cpp
    src/session_watcher.cpp
    src/file_dialog.cpp
)
target_include_directories(phylaxbox_desktop_lib PUBLIC src ${PB_GENERATED_DIR})
target_compile_definitions(phylaxbox_desktop_lib PUBLIC
    PB_DROPBOX_APP_KEY="${PB_DROPBOX_APP_KEY}"
    PB_VERSION_STRING="${PB_VERSION}"
    $<$<CONFIG:Debug>:PB_WEBVIEW_DEVTOOLS=1>)
target_link_libraries(phylaxbox_desktop_lib PUBLIC
    phylaxbox::core
    webview::core
    httplib::httplib
    OpenSSL::SSL
    OpenSSL::Crypto
)
if(WIN32)
    target_link_libraries(phylaxbox_desktop_lib PUBLIC shell32 ole32 comctl32 wtsapi32)
endif()

add_executable(PhylaxBox WIN32 src/desktop_app.cpp)
target_link_libraries(PhylaxBox PRIVATE phylaxbox_desktop_lib)
if(MSVC)
    # GUI subsystem without a console window, but keep the standard main().
    target_link_options(PhylaxBox PRIVATE /ENTRY:mainCRTStartup)
endif()
if(NOT WIN32)
    set_target_properties(PhylaxBox PROPERTIES OUTPUT_NAME phylaxbox)
endif()

install(TARGETS PhylaxBox RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT desktop)
if(UNIX AND NOT APPLE)
    install(FILES ${PROJECT_SOURCE_DIR}/packaging/linux/phylaxbox.desktop
            DESTINATION ${CMAKE_INSTALL_DATADIR}/applications COMPONENT desktop)
    install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/frontend/resources/logo.png
            DESTINATION ${CMAKE_INSTALL_DATADIR}/icons/hicolor/256x256/apps
            RENAME phylaxbox.png COMPONENT desktop)
endif()
