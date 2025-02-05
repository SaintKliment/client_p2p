#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>
#include <utility>
#include <vector>

class CryptoUtils {
public:

    static std::pair<std::string, std::string> generateECDSAKeys();

    static std::string generateIDFromPublicKey(const std::string& publicKey);

    static std::string encryptPrivateKey(const std::string& privateKey, const std::string& password);
    static std::string decryptPrivateKey(const std::string& encryptedHex, const std::string& password);

    static std::string hashPIN(const std::string& pin);

private:
    static bool secp256k1_rand256(unsigned char* data);
};

#endif // CRYPTO_H