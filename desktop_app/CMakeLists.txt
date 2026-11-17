cmake_minimum_required(VERSION 3.20)
project(DesktopApp CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Definição dos caminhos das bibliotecas (ajuste conforme necessário)
set(OPENSSL_ROOT_DIR "D:/cpp/OpenSSL-Win64")  # Ajuste para o caminho real
set(SODIUM_ROOT_DIR "D:/cpp/libsodium") # Ajuste para o caminho real
set(ZLIB_ROOT_DIR "D:/cpp/zlib-1.3.1")

set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
set(OPENSSL_LIB_DIR "${OPENSSL_ROOT_DIR}/lib")

# Caminho para as bibliotecas (ajuste conforme necessário)
set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_LIB_DIR}/VC/x64/MT/libcrypto.lib")
set(OPENSSL_SSL_LIBRARY "${OPENSSL_LIB_DIR}/VC/x64/MT/libssl.lib")


# Encontrando OpenSSL
#find_package(OpenSSL REQUIRED)

#if(NOT OpenSSL_FOUND)
#    message(FATAL_ERROR "OpenSSL não encontrado.")
#endif()

# Configurando libsodium manualmente
set(SODIUM_INCLUDE_DIR "${SODIUM_ROOT_DIR}/include")
set(SODIUM_LIBRARY "${SODIUM_ROOT_DIR}/x64/Release/v143/static/libsodium.lib")
add_definitions(-DSODIUM_STATIC)

include(FetchContent)

FetchContent_Declare(
    webview
    GIT_REPOSITORY https://github.com/webview/webview
    GIT_TAG 0.12.0)
FetchContent_MakeAvailable(webview)

FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG v1.12.0  # Mude para a versão desejada
)
FetchContent_MakeAvailable(spdlog)

# Configurando zlib manualmente
set(ZLIB_INCLUDE_DIR "${ZLIB_ROOT_DIR}")
set(ZLIB_LIBRARY "${ZLIB_ROOT_DIR}/build/Release/zlibstatic.lib")

set(JSON_INCLUDE_DIR "D:/cpp/libs/json/include")
set(HTTPLIB_INCLUDE_DIR "D:/cpp/libs/cpp-httplib")

# Criando o executável
file(GLOB SRC_FILES "src/*.cpp")
add_executable(DesktopApp ${SRC_FILES})

# Incluindo os diretórios de cabeçalhos
target_include_directories(DesktopApp PRIVATE ${SODIUM_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR} ${ZLIB_INCLUDE_DIR} ${JSON_INCLUDE_DIR} ${HTTPLIB_INCLUDE_DIR})

# Linkando as bibliotecas
target_link_libraries(DesktopApp PRIVATE webview::core spdlog::spdlog ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY} ${SODIUM_LIBRARY} ${ZLIB_LIBRARY})

# Definição de macros, caso necessário
add_definitions(-D_CRT_SECURE_NO_WARNINGS)
