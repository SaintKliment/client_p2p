#ifndef TORW_H
#define TORW_H

#include <string>
#include <thread>
#include <boost/filesystem.hpp>
#include <sys/stat.h> // Для mkdir

class Torw {
public:
    // Конструктор
    Torw();

    // Деструктор
    ~Torw();

    // Метод для запуска Tor
    void start_tor(const char* tor_path);
    // Функция для получения .onion адреса
    std::string get_onion_address();
private:
    // Флаг, указывающий на работу Tor
    bool is_running;

    // Поток для запуска Tor
    std::thread tor_thread;

    // Внутренний метод для работы Tor
    void run_tor(const std::string& tor_path);
};

#endif // TORW_H