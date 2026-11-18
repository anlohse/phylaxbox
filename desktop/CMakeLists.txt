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

# Everything but main(), so the integration tests can link it.
add_library(phylaxbox_desktop_lib STATIC
    src/appui.cpp
    src/phylaxboxframework.cpp
    src/httplib_transport.cpp
    src/oauth_loopback.cpp
    src/dropbox_link.cpp
)
target_include_directories(phylaxbox_desktop_lib PUBLIC src)
target_compile_definitions(phylaxbox_desktop_lib PUBLIC
    PB_DROPBOX_APP_KEY="${PB_DROPBOX_APP_KEY}"
    PB_VERSION_STRING="${PB_VERSION}")
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
