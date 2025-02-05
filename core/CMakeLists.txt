# Создаем статическую библиотеку core
add_library(core STATIC
    ./crypto/Crypto.cpp
    ./crypto/Crypto.h
    ./nm/NetworkManager.cpp
    ./nm/NetworkManager.h
    ./node/Node.cpp
    ./node/Node.h
    ./serialization/Serialization.cpp 
    ./serialization/Serialization.h   
    ./utils/Utils.cpp
    ./contact/Contact.cpp
    ./tor_work/Torw.cpp
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