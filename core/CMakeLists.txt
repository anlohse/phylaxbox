# PhylaxBox Core: vault domain, cryptography, serialization, compression,
# persistence and cloud synchronization logic. No UI, no TLS stack, no OS
# integration — those live in the applications and are injected through
# interfaces (e.g. sync::http_transport).
find_package(unofficial-sodium CONFIG REQUIRED)
find_package(ZLIB REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

add_library(phylaxbox_core STATIC
    crypto/crypto.cpp
    crypto/password_generator.cpp
    vault/vault_file.cpp
    vault/zlibutils.cpp
    vault/recovery_key.cpp
    storage/file_io.cpp
    storage/configservice.cpp
    storage/vault_store.cpp
    storage/device_id.cpp
    sync/dropbox_oauth.cpp
    sync/dropbox_storage.cpp
    sync/storage_factory.cpp
    models/pbexceptions.cpp
    models/vault_document.cpp
    models/entry_ops.cpp
)
add_library(phylaxbox::core ALIAS phylaxbox_core)

# Includes are written relative to this directory: "crypto/crypto.h".
target_include_directories(phylaxbox_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(phylaxbox_core PUBLIC
    unofficial-sodium::sodium
    ZLIB::ZLIB
    nlohmann_json::nlohmann_json
)
