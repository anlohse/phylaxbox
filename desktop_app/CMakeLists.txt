cmake_minimum_required(VERSION 3.25)

project(PhylaxBox VERSION 0.1.0 LANGUAGES CXX)

option(PB_BUILD_APP "Build the desktop application" ON)
option(PB_BUILD_TESTS "Build the unit tests" ON)
# Public app key of the Dropbox app (PKCE public client: there is no secret).
# Register the redirect URI http://127.0.0.1:8881/phylaxbox/callback for it.
set(PB_DROPBOX_APP_KEY "" CACHE STRING "Dropbox app key")

set(CMAKE_CXX_STANDARD 17)
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

# ---------------------------------------------------------------------------
# Core library: crypto, vault container, local config. No UI, no network.
# This is the part that must stay portable (desktop today, Android later).
# ---------------------------------------------------------------------------
find_package(unofficial-sodium CONFIG REQUIRED)
find_package(ZLIB REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

add_library(phylaxbox_core STATIC
    src/core/crypto.cpp
    src/core/vault_file.cpp
    src/core/zlibutils.cpp
    src/core/file_io.cpp
    src/core/configservice.cpp
    src/core/pbexceptions.cpp
)
target_include_directories(phylaxbox_core PUBLIC src/core)
target_link_libraries(phylaxbox_core PUBLIC
    unofficial-sodium::sodium
    ZLIB::ZLIB
    nlohmann_json::nlohmann_json
)

# ---------------------------------------------------------------------------
# Sync library: cloud storage clients over an abstract HTTP transport
# (portable and testable without network; the TLS transport lives in the app).
# ---------------------------------------------------------------------------
add_library(phylaxbox_sync STATIC
    src/sync/dropbox_oauth.cpp
    src/sync/dropbox_storage.cpp
    src/sync/storage_factory.cpp
)
target_include_directories(phylaxbox_sync PUBLIC src/sync)
target_link_libraries(phylaxbox_sync PUBLIC phylaxbox_core)

# ---------------------------------------------------------------------------
# Desktop application
# ---------------------------------------------------------------------------
if(PB_BUILD_APP)
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

    # Everything but main(), so the app tests can link it.
    add_library(phylaxbox_app STATIC
        src/app/appui.cpp
        src/app/phylaxboxframework.cpp
        src/app/httplib_transport.cpp
        src/app/oauth_loopback.cpp
        src/app/dropbox_link.cpp
    )
    target_include_directories(phylaxbox_app PUBLIC src/app)
    target_compile_definitions(phylaxbox_app PUBLIC PB_DROPBOX_APP_KEY="${PB_DROPBOX_APP_KEY}")
    target_link_libraries(phylaxbox_app PUBLIC
        phylaxbox_sync
        webview::core
        httplib::httplib
        OpenSSL::SSL
        OpenSSL::Crypto
    )
    if(WIN32)
        target_link_libraries(phylaxbox_app PUBLIC shell32)
    endif()

    add_executable(PhylaxBox src/app/desktop_app.cpp)
    target_link_libraries(PhylaxBox PRIVATE phylaxbox_app)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(PB_BUILD_TESTS)
    enable_testing()
    find_package(GTest CONFIG REQUIRED)
    include(GoogleTest)

    add_executable(phylaxbox_tests
        tests/crypto_tests.cpp
        tests/vault_file_tests.cpp
        tests/configservice_tests.cpp
        tests/dropbox_tests.cpp
    )
    target_link_libraries(phylaxbox_tests PRIVATE phylaxbox_sync GTest::gtest_main)
    target_compile_definitions(phylaxbox_tests PRIVATE
        PB_TEST_VECTORS_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../docs/test-vectors/vault-v1.json")
    gtest_discover_tests(phylaxbox_tests DISCOVERY_TIMEOUT 60)

    if(PB_BUILD_APP)
        add_executable(phylaxbox_app_tests tests/app/oauth_loopback_tests.cpp)
        target_include_directories(phylaxbox_app_tests PRIVATE tests)
        target_link_libraries(phylaxbox_app_tests PRIVATE phylaxbox_app GTest::gtest_main)
        gtest_discover_tests(phylaxbox_app_tests DISCOVERY_TIMEOUT 60)
    endif()
endif()
