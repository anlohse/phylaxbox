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
FetchContent_MakeAvailable(webview)

# Everything but main(), so the integration tests can link it.
add_library(phylaxbox_desktop_lib STATIC
    src/appui.cpp
    src/phylaxboxframework.cpp
    src/httplib_transport.cpp
    src/oauth_loopback.cpp
    src/dropbox_link.cpp
)
target_include_directories(phylaxbox_desktop_lib PUBLIC src)
target_compile_definitions(phylaxbox_desktop_lib PUBLIC PB_DROPBOX_APP_KEY="${PB_DROPBOX_APP_KEY}")
target_link_libraries(phylaxbox_desktop_lib PUBLIC
    phylaxbox::core
    webview::core
    httplib::httplib
    OpenSSL::SSL
    OpenSSL::Crypto
)
if(WIN32)
    target_link_libraries(phylaxbox_desktop_lib PUBLIC shell32)
endif()

add_executable(PhylaxBox src/desktop_app.cpp)
target_link_libraries(PhylaxBox PRIVATE phylaxbox_desktop_lib)
