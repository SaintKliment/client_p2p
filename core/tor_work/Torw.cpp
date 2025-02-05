#include "Torw.h"
#include <iostream>
#include <cstdlib> // Для system()
#include <stdexcept>
#include <atomic>
#include <boost/filesystem.hpp>
#include <sys/stat.h> // Для mkdir

Torw::Torw() : is_running(false) {}

Torw::~Torw() {
    if (tor_thread.joinable()) {
        tor_thread.join(); // Ждём завершения потока при уничтожении объекта
    }
}


void Torw::start_tor(const char* tor_path) {


    if (!is_running) {
        // Запускаем Tor в отдельном потоке
        tor_thread = std::thread(&Torw::run_tor, this, std::string(tor_path));
        is_running = true;
        std::cout << "Tor запущен в отдельном потоке." << std::endl;
    } else {
        std::cout << "Tor уже запущен." << std::endl;
    }

   
}


void Torw::run_tor(const std::string& tor_path){
     // Создаём директории для данных Tor
    const char* data_dir = "./tor_data";
    const char* hidden_service_dir = "./hidden_service";
    mkdir(data_dir, 0700);
    mkdir(hidden_service_dir, 0700);

    // Конфигурация Tor
    std::string torrc_content = R"(
        SocksPort 9050
        DataDirectory ./tor_data
        Log notice file ./tor.log
        HiddenServiceDir ./hidden_service/
        HiddenServicePort 80 127.0.0.1:8080
        
        Log notice file ./tor.log
        Log info file ./tor_info.log
        Log debug file ./tor_debug.log

        Log warn file ./tor_warn.log
        Log err file ./tor_err.log
    )";

    // Записываем конфигурацию в файл
    // const char* torrc_file = "./torrc";
    const std::string torrc_file = "./torrc";
    std::ofstream torrc(torrc_file);
    torrc << torrc_content;
    torrc.close();

    // Запускаем Tor как подпроцесс
    pid_t pid = fork();
    if (pid == 0) {
        // // Дочерний процесс
        // execl(tor_path, "tor", "-f", torrc_file, nullptr);
        execl(tor_path.c_str(), "tor", "-f", torrc_file.c_str(), nullptr);
        // Если execl вернул управление, значит произошла ошибка
        std::cerr << "Ошибка запуска Tor: " << strerror(errno) << std::endl;
        exit(1);
    } else if (pid > 0) {
        // Родительский процесс
        std::cout << "Tor запущен с PID: " << pid << std::endl;
    } else {
        // Ошибка fork
        std::cerr << "Ошибка fork: " << strerror(errno) << std::endl;
        exit(1);
    }
}


// Функция для получения .onion адреса
std::string Torw::get_onion_address() {
    const char* hostname_file = "./hidden_service/hostname";
    std::ifstream file(hostname_file);
    if (!file.is_open()) {
        std::cerr << "Не удалось открыть файл hostname!" << std::endl;
        return "";
    }

    std::string onion_address;
    std::getline(file, onion_address);
    return onion_address;
}