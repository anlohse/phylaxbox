find_package(GTest CONFIG REQUIRED)
include(GoogleTest)

# Core tests: no network, no UI.
add_executable(phylaxbox_core_tests
    crypto/crypto_tests.cpp
    crypto/vault_file_tests.cpp
    crypto/recovery_key_tests.cpp
    crypto/secure_allocator_tests.cpp
    crypto/password_generator_tests.cpp
    crypto/passphrase_generator_tests.cpp
    unit/configservice_tests.cpp
    unit/dropbox_tests.cpp
    unit/vault_document_tests.cpp
    unit/vault_store_tests.cpp
    unit/entry_ops_tests.cpp
    unit/settings_tests.cpp
    unit/site_match_tests.cpp
)
target_include_directories(phylaxbox_core_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(phylaxbox_core_tests PRIVATE phylaxbox::core GTest::gtest_main)
target_compile_definitions(phylaxbox_core_tests PRIVATE
    PB_TEST_VECTORS_FILE="${PROJECT_SOURCE_DIR}/docs/vault-format/test-vectors/vault-v1.json")
gtest_discover_tests(phylaxbox_core_tests DISCOVERY_TIMEOUT 60)

# Native host and local IPC tests (no UI needed, so CI runs them too).
if(PB_BUILD_NATIVE_HOST)
    add_executable(phylaxbox_host_tests integration/ipc_tests.cpp)
    target_include_directories(phylaxbox_host_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(phylaxbox_host_tests PRIVATE phylaxbox_native_host_lib GTest::gtest_main)
    gtest_discover_tests(phylaxbox_host_tests DISCOVERY_TIMEOUT 60)
endif()

# Desktop tests: unit tests of desktop components and integration tests
# against real local sockets.
if(PB_BUILD_DESKTOP)
    add_executable(phylaxbox_desktop_tests
        unit/vault_bridge_tests.cpp
        unit/browser_protocol_tests.cpp
        integration/oauth_loopback_tests.cpp
        integration/app_webview_tests.cpp
        integration/secret_clipboard_tests.cpp
    )
    target_include_directories(phylaxbox_desktop_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(phylaxbox_desktop_tests PRIVATE phylaxbox_desktop_lib GTest::gtest_main)
    if(PB_BUILD_NATIVE_HOST)
        # End-to-end: extension messages -> native host relay -> IPC -> app.
        target_sources(phylaxbox_desktop_tests PRIVATE integration/native_host_tests.cpp)
        target_link_libraries(phylaxbox_desktop_tests PRIVATE phylaxbox_native_host_lib)
    endif()
    gtest_discover_tests(phylaxbox_desktop_tests DISCOVERY_TIMEOUT 60)
endif()
