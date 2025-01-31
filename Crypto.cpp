#include "Crypto.h"
#include <secp256k1.h>
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdio>
#include <iostream>


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

std::string CryptoUtils::toHex(const unsigned char* data, size_t length) {
    std::stringstream ss;
    for (size_t i = 0; i < length; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return ss.str();
}