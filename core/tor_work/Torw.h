#ifndef TORW_H
#define TORW_H

#include <string>
#include <thread>
#include <boost/filesystem.hpp>
#include <sys/stat.h> // Для mkdir

class Torw {
public:
    Torw();

    std::string get_onion_address();

    static void check_tor_before_start(std::string& server_port);
    void start_tor(const char* tor_path, std::string& server_port);

private:
    bool is_running;

    void run_tor(const std::string& tor_path, std::string& server_port);
};

#endif // TORW_H