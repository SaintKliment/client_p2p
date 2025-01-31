#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>
#include <utility>

class CryptoUtils {
public:

    static std::pair<std::string, std::string> generateECDSAKeys();

    static std::string generateIDFromPublicKey(const std::string& publicKey);

    static std::string toHex(const unsigned char* data, size_t length);

private:
    static bool secp256k1_rand256(unsigned char* data);
};

#endif // CRYPTO_H