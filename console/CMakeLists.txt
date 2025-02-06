# Создаем исполняемый файл для консольного приложения
add_executable(console main_console.cpp UserInputCollector.cpp)

# Включение заголовочных файлов Boost (если они используются в консольном приложении)
find_package(Boost REQUIRED COMPONENTS filesystem system)
if (Boost_FOUND)
    message(STATUS "Boost found: ${Boost_INCLUDE_DIRS}")
    include_directories(${Boost_INCLUDE_DIRS})
endif()

# Поиск и использование других необходимых библиотек через PkgConfig
find_package(PkgConfig REQUIRED)

# GLib
pkg_check_modules(GLIB REQUIRED glib-2.0)
include_directories(${GLIB_INCLUDE_DIRS})

# NICE (библиотека для ICE)
pkg_check_modules(NICE REQUIRED nice)
include_directories(${NICE_INCLUDE_DIRS})

# SECP256K1 (эллиптические кривые)
pkg_check_modules(SECP256K1 REQUIRED libsecp256k1)
include_directories(${SECP256K1_INCLUDE_DIRS})

# miniupnpc (UPnP для проброса портов)
pkg_check_modules(MINIUPNPC REQUIRED miniupnpc)
include_directories(${MINIUPNPC_INCLUDE_DIRS})

# cURL (HTTP-клиент)
find_package(CURL REQUIRED)
include_directories(${CURL_INCLUDE_DIRS})

# OpenSSL (криптография)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Связываем все зависимости с консольным приложением
target_link_libraries(console PRIVATE
    core  # Ядро проекта

    ${GLIB_LIBRARIES}  # GLib
    ${NICE_LIBRARIES}  # NICE
    ${SECP256K1_LIBRARIES}  # SECP256K1
    ${MINIUPNPC_LIBRARIES}  # miniupnpc
    CURL::libcurl  # cURL
    OpenSSL::Crypto  # OpenSSL Crypto
    ${Boost_LIBRARIES}  # Boost (если используется)
)