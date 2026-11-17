cmake_minimum_required(VERSION 3.25)

project(PhylaxBox VERSION 0.1.0 LANGUAGES CXX)

option(PB_BUILD_DESKTOP "Build the desktop application" ON)
option(PB_BUILD_NATIVE_HOST "Build the browser native messaging host" ON)
option(PB_BUILD_TESTS "Build the tests" ON)
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

# Shared, platform-independent core (crypto, vault, storage, sync, models).
add_subdirectory(core)

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
