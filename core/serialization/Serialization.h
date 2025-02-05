#ifndef SERIALIZATION_H
#define SERIALIZATION_H

#include <string>
#include <vector>

class Serialization {
public:
    static std::string bytesToHex(const unsigned char* data, size_t length);
    static std::vector<unsigned char> hexToBytes(const std::string& hex);
};

#endif // SERIALIZATION_H