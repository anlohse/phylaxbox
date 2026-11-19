# Local IPC between the native messaging host and the desktop app (spec §9.3).
# Shared by both executables; no third-party dependencies.
add_library(phylaxbox_ipc STATIC local_channel.cpp)
add_library(phylaxbox::ipc ALIAS phylaxbox_ipc)
# Includes are written from the repository root: "ipc/local_channel.h".
target_include_directories(phylaxbox_ipc PUBLIC ${PROJECT_SOURCE_DIR})
if(WIN32)
    target_link_libraries(phylaxbox_ipc PUBLIC advapi32)
endif()
