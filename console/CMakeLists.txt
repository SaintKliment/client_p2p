# Создаем исполняемый файл console
add_executable(console main_console.cpp)

# Связываем консольное приложение с ядром и библиотеками
target_link_libraries(console PRIVATE
    core
    PkgConfig::GLIB
    PkgConfig::NICE
    PkgConfig::SECP256K1
    PkgConfig::MINIUPNPC
    CURL::libcurl
    OpenSSL::Crypto # Добавляем OpenSSL
    
)

