# Installer configuration, included from the top-level CMakeLists.txt.
#   Windows: NSIS installer (.exe) + portable ZIP
#   Linux:   Debian package (.deb) + TGZ
# Build with:  cpack --config <build>/CPackConfig.cmake -C Release

set(CPACK_PACKAGE_NAME "PhylaxBox")
set(CPACK_PACKAGE_VENDOR "PhylaxBox")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PROJECT_DESCRIPTION}")
set(CPACK_PACKAGE_HOMEPAGE_URL "${PROJECT_HOMEPAGE_URL}")
set(CPACK_PACKAGE_VERSION "${PB_VERSION}")
set(CPACK_PACKAGE_VERSION_MAJOR "${PROJECT_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${PROJECT_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${PROJECT_VERSION_PATCH}")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "PhylaxBox")
# Shown by installers. Replace with the project LICENSE once one is chosen.
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_LIST_DIR}/installer-notice.txt")
set(CPACK_STRIP_FILES ON)
# Monolithic packages: only the desktop app and native host have install
# rules (tests and dependencies install nothing).

if(WIN32)
    set(CPACK_GENERATOR "NSIS;ZIP")
    set(CPACK_PACKAGE_FILE_NAME "PhylaxBox-${PB_VERSION}-windows-x64")
    set(CPACK_PACKAGE_EXECUTABLES "PhylaxBox;PhylaxBox")
    set(CPACK_NSIS_INSTALL_ROOT "$PROGRAMFILES64")
    set(CPACK_NSIS_DISPLAY_NAME "PhylaxBox")
    set(CPACK_NSIS_PACKAGE_NAME "PhylaxBox ${PB_VERSION}")
    set(CPACK_NSIS_INSTALLED_ICON_NAME "bin\\\\PhylaxBox.exe")
    set(CPACK_NSIS_URL_INFO_ABOUT "${PROJECT_HOMEPAGE_URL}")
    set(CPACK_NSIS_ENABLE_UNINSTALL_BEFORE_INSTALL ON)
    set(CPACK_NSIS_MODIFY_PATH OFF)
    set(CPACK_NSIS_EXECUTABLES_DIRECTORY "bin")
    set(CPACK_NSIS_MUI_FINISHPAGE_RUN "PhylaxBox.exe")
elseif(UNIX AND NOT APPLE)
    set(CPACK_GENERATOR "DEB;TGZ")
    set(CPACK_PACKAGE_FILE_NAME "phylaxbox-${PB_VERSION}-linux-x86_64")
    set(CPACK_PACKAGING_INSTALL_PREFIX "/usr")

    # Debian versions: "-" separates the package revision, "~" sorts before
    # the release, so 1.2.0-beta.1 becomes 1.2.0~beta.1.
    string(REPLACE "-" "~" PB_DEB_VERSION "${PB_VERSION}")
    set(CPACK_DEBIAN_PACKAGE_NAME "phylaxbox")
    set(CPACK_DEBIAN_PACKAGE_VERSION "${PB_DEB_VERSION}")
    set(CPACK_DEBIAN_FILE_NAME "phylaxbox_${PB_DEB_VERSION}_amd64.deb")
    set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
    set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER "PhylaxBox developers")
    # Runtime libraries (GTK, WebKitGTK...) computed from the binary.
    set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
    # CA certificates are read from /etc/ssl/certs for HTTPS.
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "ca-certificates")
endif()

include(CPack)
