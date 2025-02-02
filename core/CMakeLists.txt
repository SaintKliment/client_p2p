# Создаем статическую библиотеку core
add_library(core STATIC
    Crypto.cpp
    Crypto.h
    NetworkManager.cpp
    NetworkManager.h
    Node.cpp
    Node.h
    Serialization.cpp 
    Serialization.h   
)

# Подключаем заголовочные файлы
target_include_directories(core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Связываем библиотеки
target_link_libraries(core PRIVATE
    PkgConfig::GLIB
    PkgConfig::NICE
    PkgConfig::SECP256K1
    PkgConfig::MINIUPNPC
    CURL::libcurl
    OpenSSL::Crypto 
)