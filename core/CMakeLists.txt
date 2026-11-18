# PhylaxBox Core: vault domain, cryptography, serialization, compression,
# persistence and cloud synchronization logic. No UI, no TLS stack, no OS
# integration — those live in the applications and are injected through
# interfaces (e.g. sync::http_transport).
find_package(unofficial-sodium CONFIG REQUIRED)
find_package(ZLIB REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

# EFF Long Wordlist -> generated C++ array (see crypto/data/README.md).
set(PB_WORDLIST ${CMAKE_CURRENT_SOURCE_DIR}/crypto/data/eff_large_wordlist.txt)
set(PB_WORDLIST_SHA256 addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${PB_WORDLIST})
file(SHA256 ${PB_WORDLIST} PB_WORDLIST_ACTUAL_SHA256)
if(NOT PB_WORDLIST_ACTUAL_SHA256 STREQUAL PB_WORDLIST_SHA256)
    message(FATAL_ERROR "eff_large_wordlist.txt was modified (SHA-256 ${PB_WORDLIST_ACTUAL_SHA256})")
endif()
file(STRINGS ${PB_WORDLIST} PB_WORDLIST_LINES)
set(PB_WORDLIST_BODY "")
set(PB_WORDLIST_COUNT 0)
foreach(line IN LISTS PB_WORDLIST_LINES)
    if(NOT line MATCHES "^[1-6][1-6][1-6][1-6][1-6]\t([a-z-]+)$")
        message(FATAL_ERROR "unexpected wordlist line: ${line}")
    endif()
    string(APPEND PB_WORDLIST_BODY "    \"${CMAKE_MATCH_1}\",\n")
    math(EXPR PB_WORDLIST_COUNT "${PB_WORDLIST_COUNT} + 1")
endforeach()
if(NOT PB_WORDLIST_COUNT EQUAL 7776)
    message(FATAL_ERROR "the EFF long wordlist must have 7776 words, found ${PB_WORDLIST_COUNT}")
endif()
set(PB_CORE_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
file(WRITE ${PB_CORE_GENERATED_DIR}/eff_wordlist.h.tmp
    "// Generated from core/crypto/data/eff_large_wordlist.txt. Do not edit.\n"
    "#pragma once\n\n"
    "namespace pb {\n\n"
    "inline constexpr const char* EFF_LONG_WORDLIST[] = {\n"
    "${PB_WORDLIST_BODY}"
    "};\n\n"
    "} // namespace pb\n")
configure_file(${PB_CORE_GENERATED_DIR}/eff_wordlist.h.tmp ${PB_CORE_GENERATED_DIR}/eff_wordlist.h COPYONLY)

add_library(phylaxbox_core STATIC
    crypto/crypto.cpp
    crypto/password_generator.cpp
    crypto/passphrase_generator.cpp
    vault/vault_file.cpp
    vault/zlibutils.cpp
    vault/recovery_key.cpp
    storage/file_io.cpp
    storage/configservice.cpp
    storage/vault_store.cpp
    storage/device_id.cpp
    storage/device_settings.cpp
    sync/dropbox_oauth.cpp
    sync/dropbox_storage.cpp
    sync/storage_factory.cpp
    models/pbexceptions.cpp
    models/vault_document.cpp
    models/entry_ops.cpp
    models/vault_preferences.cpp
)
add_library(phylaxbox::core ALIAS phylaxbox_core)

# Includes are written relative to this directory: "crypto/crypto.h".
target_include_directories(phylaxbox_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
                                          PRIVATE ${PB_CORE_GENERATED_DIR})
target_link_libraries(phylaxbox_core PUBLIC
    unofficial-sodium::sodium
    ZLIB::ZLIB
    nlohmann_json::nlohmann_json
)
