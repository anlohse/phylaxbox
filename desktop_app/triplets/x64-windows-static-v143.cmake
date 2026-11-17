# x64-windows-static pinned to the VS 2022 (v143) toolset.
# vcpkg otherwise picks the newest Visual Studio installed, whose STL may not
# link with objects built by the "Visual Studio 17 2022" CMake generator.
set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE static)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_PLATFORM_TOOLSET v143)
