#ifndef UTILS_H
#define UTILS_H

#include <string>

class Utils {
public:
    static bool fileExists(const std::string& filename);
    static void free_port(int port);
    static void login(const std::string& privateKeyFilename,const std::string& publicKeyFilename,const std::string& pinHashFilename,std::string& hexPublicMasterKey,std::string& hexPrivateMasterKey);
    static std::pair<std::string, std::string> generateSessionKeys();
private:
    // static bool secp256k1_rand256(unsigned char* data);
};

#endif