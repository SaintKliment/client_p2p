#include "Crypto.h"
#include <secp256k1.h>
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdio>
#include <iostream>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <cctype>
#include <vector>
#include "./serialization/Serialization.h"
#include <openssl/sha.h>

#define AES_KEY_LENGTH 32 // Для AES-256
#define AES_BLOCK_SIZE 16


bool CryptoUtils::secp256k1_rand256(unsigned char* data) {
    FILE* urandom = fopen("/dev/urandom", "rb");
    if (!urandom) {
        return false;
    }
    size_t readBytes = fread(data, 1, 32, urandom);
    fclose(urandom);
    return readBytes == 32;
}

std::pair<std::string, std::string> CryptoUtils::generateECDSAKeys() {
    // Инициализируем контекст secp256k1
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        std::cerr << "Error creating secp256k1 context" << std::endl;
        return { "", "" };
    }

    // Генерируем приватный ключ
    unsigned char privateKey[32];
    if (!secp256k1_rand256(privateKey)) {
        std::cerr << "Error generating random private key" << std::endl;
        secp256k1_context_destroy(ctx);
        return { "", "" };
    }

    // Создаем структуру для публичного ключа
    secp256k1_pubkey publicKey;
    if (!secp256k1_ec_pubkey_create(ctx, &publicKey, privateKey)) {
        std::cerr << "Error generating public key" << std::endl;
        secp256k1_context_destroy(ctx);
        return { "", "" };
    }

    // Сериализуем публичный ключ в формат DER
    unsigned char serializedPublicKey[65];
    size_t serializedPublicKeyLen = 65;
    if (!secp256k1_ec_pubkey_serialize(ctx, serializedPublicKey, &serializedPublicKeyLen, &publicKey, SECP256K1_EC_UNCOMPRESSED)) {
        std::cerr << "Error serializing public key" << std::endl;
        secp256k1_context_destroy(ctx);
        return { "", "" };
    }

    // Преобразуем приватный и публичный ключи в строки
    std::string publicKeyStr(reinterpret_cast<char*>(serializedPublicKey), serializedPublicKeyLen);
    std::string privateKeyStr(reinterpret_cast<char*>(privateKey), sizeof(privateKey));

    // Освобождаем контекст
    secp256k1_context_destroy(ctx);

    return { publicKeyStr, privateKeyStr };
}

std::string CryptoUtils::generateIDFromPublicKey(const std::string& publicKey) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating EVP context" << std::endl;
        return "";
    }
    const EVP_MD* md = EVP_sha256();
    if (!EVP_DigestInit_ex(ctx, md, nullptr)) {
        std::cerr << "Error initializing digest" << std::endl;
        EVP_MD_CTX_free(ctx);
        return "";
    }
    if (!EVP_DigestUpdate(ctx, publicKey.data(), publicKey.size())) {
        std::cerr << "Error updating digest" << std::endl;
        EVP_MD_CTX_free(ctx);
        return "";
    }
    if (!EVP_DigestFinal_ex(ctx, hash, &hashLen)) {
        std::cerr << "Error finalizing digest" << std::endl;
        EVP_MD_CTX_free(ctx);
        return "";
    }
    EVP_MD_CTX_free(ctx);

    std::stringstream ss;
    for (unsigned int i = 0; i < hashLen; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

std::string CryptoUtils::encryptPrivateKey(const std::string& privateKey, const std::string& password) {
    unsigned char iv[AES_BLOCK_SIZE];
    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        throw std::runtime_error("Failed to generate IV");
    }

    unsigned char key[AES_KEY_LENGTH];
    PKCS5_PBKDF2_HMAC(password.c_str(), password.size(), nullptr, 0, 10000, EVP_sha256(), AES_KEY_LENGTH, key);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encryption");
    }

    std::vector<unsigned char> paddedData(privateKey.begin(), privateKey.end());
    int padding = AES_BLOCK_SIZE - (paddedData.size() % AES_BLOCK_SIZE);
    paddedData.insert(paddedData.end(), padding, static_cast<unsigned char>(padding));

    std::vector<unsigned char> encryptedData(paddedData.size() + AES_BLOCK_SIZE);
    int len;
    if (EVP_EncryptUpdate(ctx, encryptedData.data(), &len, paddedData.data(), paddedData.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption failed");
    }

    int encryptedLen = len;
    if (EVP_EncryptFinal_ex(ctx, encryptedData.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption finalization failed");
    }
    encryptedLen += len;

    EVP_CIPHER_CTX_free(ctx);

    encryptedData.resize(encryptedLen);

    std::vector<unsigned char> result;
    result.insert(result.end(), iv, iv + AES_BLOCK_SIZE);
    result.insert(result.end(), encryptedData.begin(), encryptedData.end());

    return Serialization::bytesToHex(result.data(), result.size());
}

std::string CryptoUtils::decryptPrivateKey(const std::string& encryptedHex, const std::string& password) {
    std::vector<unsigned char> encryptedData = Serialization::hexToBytes(encryptedHex);

    if (encryptedData.size() < AES_BLOCK_SIZE) {
        throw std::runtime_error("Invalid encrypted data");
    }

    unsigned char iv[AES_BLOCK_SIZE];
    std::copy(encryptedData.begin(), encryptedData.begin() + AES_BLOCK_SIZE, iv);

    std::vector<unsigned char> cipherText(encryptedData.begin() + AES_BLOCK_SIZE, encryptedData.end());

    unsigned char key[AES_KEY_LENGTH];
    PKCS5_PBKDF2_HMAC(password.c_str(), password.size(), nullptr, 0, 10000, EVP_sha256(), AES_KEY_LENGTH, key);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize decryption");
    }

    std::vector<unsigned char> decryptedData(cipherText.size());
    int len;
    if (EVP_DecryptUpdate(ctx, decryptedData.data(), &len, cipherText.data(), cipherText.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption failed");
    }

    int decryptedLen = len;
    if (EVP_DecryptFinal_ex(ctx, decryptedData.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption finalization failed");
    }
    decryptedLen += len;

    EVP_CIPHER_CTX_free(ctx);

    decryptedData.resize(decryptedLen);

    int padding = decryptedData.back();
    if (padding < 1 || padding > AES_BLOCK_SIZE) {
        throw std::runtime_error("Invalid padding");
    }
    decryptedData.resize(decryptedData.size() - padding);

    return std::string(decryptedData.begin(), decryptedData.end());
}

std::string CryptoUtils::hashPIN(const std::string& pin) {
    const size_t HASH_LENGTH = 32; // Длина хеша SHA-256 (32 байта)
    unsigned char hash[HASH_LENGTH];
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_sha256();

    if (!mdctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (1 != EVP_DigestInit_ex(mdctx, md, nullptr)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to initialize digest context");
    }

    if (1 != EVP_DigestUpdate(mdctx, pin.c_str(), pin.size())) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to update digest");
    }

    unsigned int hashLength = HASH_LENGTH;
    if (1 != EVP_DigestFinal_ex(mdctx, hash, &hashLength)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to finalize digest");
    }

    EVP_MD_CTX_free(mdctx);

    std::stringstream ss;
    for (size_t i = 0; i < hashLength; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}
