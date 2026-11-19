cmake_minimum_required(VERSION 3.25)

# Product version. Release builds pass it from the git tag (v1.2.3 -> 1.2.3);
# an optional pre-release suffix is kept for package names (1.2.3-beta.1).
set(PB_VERSION "0.0.0-dev" CACHE STRING "Product version (MAJOR.MINOR.PATCH[-suffix])")
if(NOT PB_VERSION MATCHES "^([0-9]+\\.[0-9]+\\.[0-9]+)(-[0-9A-Za-z.-]+)?$")
    message(FATAL_ERROR "PB_VERSION '${PB_VERSION}' is not MAJOR.MINOR.PATCH[-suffix]")
endif()
set(PB_VERSION_NUMERIC "${CMAKE_MATCH_1}")

project(PhylaxBox VERSION ${PB_VERSION_NUMERIC} LANGUAGES CXX
        DESCRIPTION "Privacy-first password manager with a user-owned encrypted vault"
        HOMEPAGE_URL "https://github.com/anlohse/phylaxbox")

option(PB_BUILD_DESKTOP "Build the desktop application" ON)
option(PB_BUILD_NATIVE_HOST "Build the browser native messaging host" ON)
option(PB_BUILD_TESTS "Build the tests" ON)
# Public app key of the Dropbox app (PKCE public client: there is no secret).
# Register the redirect URI http://127.0.0.1:8881/phylaxbox/callback for it.
set(PB_DROPBOX_APP_KEY "" CACHE STRING "Dropbox app key")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    # Must match the vcpkg x64-windows-static triplet (/MT).
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    add_compile_options(/W4 /utf-8 /permissive-)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Shared, platform-independent core (crypto, vault, storage, sync, models).
add_subdirectory(core)

# Browser extension identities (browser-extension/extension-ids.json): the
# desktop app accepts only these extensions, and the native host manifests
# list them (allowed_origins / allowed_extensions).
set(PB_EXTENSION_IDS_FILE ${PROJECT_SOURCE_DIR}/browser-extension/extension-ids.json)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${PB_EXTENSION_IDS_FILE})
file(READ ${PB_EXTENSION_IDS_FILE} PB_EXTENSION_IDS_JSON)
set(PB_CHROME_EXTENSION_ORIGINS "")
set(PB_FIREFOX_EXTENSION_IDS "")
foreach(browser chrome firefox)
    string(JSON count LENGTH "${PB_EXTENSION_IDS_JSON}" ${browser} ids)
    math(EXPR last "${count} - 1")
    foreach(i RANGE ${last})
        string(JSON id GET "${PB_EXTENSION_IDS_JSON}" ${browser} ids ${i})
        if(browser STREQUAL "chrome")
            if(NOT id MATCHES "^[a-p]+$")
                message(FATAL_ERROR "extension-ids.json: invalid Chrome extension id '${id}'")
            endif()
            list(APPEND PB_CHROME_EXTENSION_ORIGINS "chrome-extension://${id}/")
        else()
            if(NOT id MATCHES "^[{}@A-Za-z0-9._-]+$")
                message(FATAL_ERROR "extension-ids.json: invalid Firefox extension id '${id}'")
            endif()
            list(APPEND PB_FIREFOX_EXTENSION_IDS "${id}")
        endif()
    endforeach()
endforeach()

# The desktop app and the native host are built into the same directory (as
# they are installed), so the host can start the app.
set(PB_BIN_OUTPUT_DIR ${CMAKE_BINARY_DIR}/bin)

# Local IPC shared by the desktop app and the native messaging host.
if(PB_BUILD_DESKTOP OR PB_BUILD_NATIVE_HOST)
    add_subdirectory(ipc)
endif()

if(PB_BUILD_DESKTOP)
    add_subdirectory(desktop)
endif()

if(PB_BUILD_NATIVE_HOST)
    add_subdirectory(native-host)
endif()

if(PB_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Installers (cpack): NSIS + ZIP on Windows, DEB + TGZ on Linux.
include(packaging/CPackConfig.cmake)
