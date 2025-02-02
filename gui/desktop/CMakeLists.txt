# Создаем исполняемый файл desktop_app
add_executable(desktop_app
    main_desktop.cpp
    MainWindow.cpp
)

find_package(PkgConfig REQUIRED)

pkg_check_modules(NICE REQUIRED IMPORTED_TARGET nice)

include_directories(${NICE_INCLUDE_DIRS})
link_directories(${NICE_LIBRARY_DIRS})

target_link_libraries(desktop_app PRIVATE
    core
    Qt6::Widgets
    ${GLIB_LIBRARIES}
    ${NICE_LIBRARIES}
    ${SECP256K1_LIBRARIES}
    ${MINIUPNPC_LIBRARIES}
    ${CURL_LIBRARIES}
    ${OPENSSL_LIBRARIES}
)