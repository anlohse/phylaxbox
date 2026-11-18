# PhylaxBox Native Host: browser Native Messaging bridge to the desktop app
# (spec §9). Placeholder until the IPC protocol is designed.
configure_file(src/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/generated/config.h @ONLY)

add_executable(phylaxbox_native_host src/main.cpp)
target_include_directories(phylaxbox_native_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/generated)
set_target_properties(phylaxbox_native_host PROPERTIES OUTPUT_NAME phylaxbox-native-host)

include(GNUInstallDirs)
# Browser registration (Windows registry / NativeMessagingHosts manifests) is
# added once the extension ids and the IPC protocol exist (spec §9).
install(TARGETS phylaxbox_native_host RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT desktop)
