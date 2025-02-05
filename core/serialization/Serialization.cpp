#include "Serialization.h"
#include <sstream>
#include <iomanip>
#include <cstdlib>

std::string Serialization::bytesToHex(const unsigned char* data, size_t length) {
    std::stringstream ss;
    for (size_t i = 0; i < length; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return ss.str();
}

std::vector<unsigned char> Serialization::hexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.size(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        char byte = static_cast<char>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}