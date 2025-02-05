#include "./Utils.h"
#include <boost/filesystem.hpp>
#include <iostream>

namespace fs = boost::filesystem;


bool Utils::fileExists(const std::string& filename) {
    return fs::exists(filename);
}



void Utils::free_port(int port) {
    // Команда для поиска процесса, использующего порт
    std::string command = "sudo lsof -i:" + std::to_string(port) + " -t";
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        std::cerr << "Ошибка при выполнении команды lsof!" << std::endl;
        return;
    }

    char buffer[128];
    std::string result = "";
    while (!feof(pipe)) {
        if (fgets(buffer, 128, pipe) != nullptr) {
            result += buffer;
        }
    }
    pclose(pipe);

    // Если найден PID, завершаем процесс
    if (!result.empty()) {
        int pid = std::stoi(result);
        std::cout << "Порт " << port << " занят процессом с PID: " << pid << ". Завершаем процесс..." << std::endl;
        std::string kill_command = "sudo kill -9 " + std::to_string(pid);
        system(kill_command.c_str());
    } else {
        std::cout << "Порт " << port << " свободен." << std::endl;
    }
}
