cmake_minimum_required(VERSION 3.14)
project(MyProject)

# Настройка стандартов и автоматической генерации MOC
set(CMAKE_AUTOMOC ON) # Автоматическая генерация MOC
set(CMAKE_CXX_STANDARD 17) # Используйте стандарт C++17 или выше


# Находим pkg-config (для поиска библиотек)
find_package(PkgConfig REQUIRED)

# Ищем GLib (glib-2.0 и gobject-2.0)
pkg_check_modules(GLIB REQUIRED IMPORTED_TARGET glib-2.0 gobject-2.0)

# Ищем libnice
pkg_check_modules(NICE REQUIRED IMPORTED_TARGET nice)

# Ищем libsecp256k1
pkg_check_modules(SECP256K1 REQUIRED IMPORTED_TARGET libsecp256k1)

# Ищем miniupnpc
pkg_check_modules(MINIUPNPC REQUIRED IMPORTED_TARGET miniupnpc)

# Ищем libcurl
find_package(CURL REQUIRED)

# Ищем OpenSSL
find_package(OpenSSL REQUIRED)

find_package(Qt6 COMPONENTS Widgets REQUIRED)

# Подключаем подпроекты
add_subdirectory(core)
add_subdirectory(console)
add_subdirectory(gui/desktop) # Добавляем директорию desktop

# Устанавливаем переменные для использования в подпроектах
set(GLIB_LIBRARIES PkgConfig::GLIB)
set(NICE_LIBRARIES PkgConfig::NICE)
set(SECP256K1_LIBRARIES PkgConfig::SECP256K1)
set(MINIUPNPC_LIBRARIES PkgConfig::MINIUPNPC)
set(CURL_LIBRARIES CURL::libcurl)
set(OPENSSL_LIBRARIES OpenSSL::Crypto)
set(QT_WIDGETS Qt6::Widgets)