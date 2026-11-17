find_package(GTest CONFIG REQUIRED)
include(GoogleTest)

# Core tests: no network, no UI.
add_executable(phylaxbox_core_tests
    crypto/crypto_tests.cpp
    crypto/vault_file_tests.cpp
    unit/configservice_tests.cpp
    unit/dropbox_tests.cpp
)
target_include_directories(phylaxbox_core_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(phylaxbox_core_tests PRIVATE phylaxbox::core GTest::gtest_main)
target_compile_definitions(phylaxbox_core_tests PRIVATE
    PB_TEST_VECTORS_FILE="${PROJECT_SOURCE_DIR}/docs/vault-format/test-vectors/vault-v1.json")
gtest_discover_tests(phylaxbox_core_tests DISCOVERY_TIMEOUT 60)

# Integration tests: desktop components against real local sockets.
if(PB_BUILD_DESKTOP)
    add_executable(phylaxbox_integration_tests integration/oauth_loopback_tests.cpp)
    target_include_directories(phylaxbox_integration_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(phylaxbox_integration_tests PRIVATE phylaxbox_desktop_lib GTest::gtest_main)
    gtest_discover_tests(phylaxbox_integration_tests DISCOVERY_TIMEOUT 60)
endif()
