#ifndef UTILS_H
#define UTILS_H

#include <string>

class Utils {
public:
    static bool fileExists(const std::string& filename);
    static void free_port(int port);
private:
    // static bool secp256k1_rand256(unsigned char* data);
};

#endif