# PhylaxBox Native Host: browser Native Messaging bridge to the desktop app
# (spec §9). The relay logic is a library so the tests can drive it.
add_library(phylaxbox_native_host_lib STATIC src/relay.cpp)
target_include_directories(phylaxbox_native_host_lib PUBLIC src)
target_link_libraries(phylaxbox_native_host_lib PUBLIC phylaxbox::ipc phylaxbox::core)
target_compile_definitions(phylaxbox_native_host_lib PRIVATE PB_VERSION_STRING="${PB_VERSION}")

# A console program: browsers talk to it through stdin/stdout.
add_executable(phylaxbox_native_host src/main.cpp)
target_link_libraries(phylaxbox_native_host PRIVATE phylaxbox_native_host_lib)
# Next to the desktop app (also in the build tree), so "launch_app" finds it.
set_target_properties(phylaxbox_native_host PROPERTIES
    OUTPUT_NAME phylaxbox-native-host
    RUNTIME_OUTPUT_DIRECTORY ${PB_BIN_OUTPUT_DIR})

include(GNUInstallDirs)
install(TARGETS phylaxbox_native_host RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT desktop)

# --- Native messaging host manifests (browser registration) ------------------
# Chromium browsers (Chrome, Edge, Chromium) list allowed extension origins;
# Firefox lists add-on ids. Both come from browser-extension/extension-ids.json.
set(PB_NATIVE_HOST_NAME "com.phylaxbox.native_host")
if(WIN32)
    # Windows accepts a path relative to the manifest: both live in bin/.
    set(PB_NATIVE_HOST_PATH "phylaxbox-native-host.exe")
else()
    # Linux needs an absolute path; the packages install to /usr.
    set(PB_NATIVE_HOST_PATH "/usr/bin/phylaxbox-native-host")
endif()
set(PB_ORIGINS_JSON "")
foreach(origin IN LISTS PB_CHROME_EXTENSION_ORIGINS)
    if(PB_ORIGINS_JSON)
        string(APPEND PB_ORIGINS_JSON ", ")
    endif()
    string(APPEND PB_ORIGINS_JSON "\"${origin}\"")
endforeach()
set(PB_FIREFOX_JSON "")
foreach(id IN LISTS PB_FIREFOX_EXTENSION_IDS)
    if(PB_FIREFOX_JSON)
        string(APPEND PB_FIREFOX_JSON ", ")
    endif()
    string(APPEND PB_FIREFOX_JSON "\"${id}\"")
endforeach()
set(PB_MANIFEST_DIR ${CMAKE_CURRENT_BINARY_DIR}/manifests)
file(WRITE ${PB_MANIFEST_DIR}/chromium/${PB_NATIVE_HOST_NAME}.json
"{
  \"name\": \"${PB_NATIVE_HOST_NAME}\",
  \"description\": \"PhylaxBox native messaging host\",
  \"path\": \"${PB_NATIVE_HOST_PATH}\",
  \"type\": \"stdio\",
  \"allowed_origins\": [${PB_ORIGINS_JSON}]
}
")
file(WRITE ${PB_MANIFEST_DIR}/firefox/${PB_NATIVE_HOST_NAME}.json
"{
  \"name\": \"${PB_NATIVE_HOST_NAME}\",
  \"description\": \"PhylaxBox native messaging host\",
  \"path\": \"${PB_NATIVE_HOST_PATH}\",
  \"type\": \"stdio\",
  \"allowed_extensions\": [${PB_FIREFOX_JSON}]
}
")

if(WIN32)
    # Registered by the installer (packaging/CPackConfig.cmake: registry keys
    # under HKLM\Software\{Google\Chrome,Microsoft\Edge,Chromium,Mozilla}).
    install(FILES ${PB_MANIFEST_DIR}/chromium/${PB_NATIVE_HOST_NAME}.json
            DESTINATION ${CMAKE_INSTALL_BINDIR} RENAME ${PB_NATIVE_HOST_NAME}.chromium.json COMPONENT desktop)
    install(FILES ${PB_MANIFEST_DIR}/firefox/${PB_NATIVE_HOST_NAME}.json
            DESTINATION ${CMAKE_INSTALL_BINDIR} RENAME ${PB_NATIVE_HOST_NAME}.firefox.json COMPONENT desktop)
elseif(UNIX AND NOT APPLE)
    # Firefox reads /usr/lib/mozilla/native-messaging-hosts directly. The
    # Chromium browsers read /etc/...; the .deb links them there on install
    # (packaging/linux/postinst).
    install(FILES ${PB_MANIFEST_DIR}/firefox/${PB_NATIVE_HOST_NAME}.json
            DESTINATION lib/mozilla/native-messaging-hosts COMPONENT desktop)
    install(FILES ${PB_MANIFEST_DIR}/chromium/${PB_NATIVE_HOST_NAME}.json
            DESTINATION ${CMAKE_INSTALL_DATADIR}/phylaxbox/native-messaging COMPONENT desktop)
endif()
