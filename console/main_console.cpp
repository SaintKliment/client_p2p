#include <iostream>
#include "../core/NetworkManager.h"
#include "../core/Node.h"
#include <locale>
#include <thread>
#include <chrono>
#include "../core/Crypto.h"
#include <sys/stat.h>
#include <fstream>
#include "../core/Serialization.h"
#include <iomanip>
#include <sstream>
#include <openssl/evp.h>

namespace fs = std::filesystem;

bool fileExists(const std::string& filename) {
    return fs::exists(filename);
}

std::string getPINFromUser(bool isFirstTime) {
    std::string pin;
    while (true) {
        std::cout << (isFirstTime ? "Придумайте 6-значный PIN-код: " : "Введите 6-значный PIN-код: ");
        std::cin >> pin;
        if (pin.length() == 6 && pin.find_first_not_of("0123456789") == std::string::npos) {
            return pin;
        }
        std::cout << "Ошибка: PIN-код должен состоять из 6 цифр. Попробуйте снова." << std::endl;
    }
}


int main() {
    setlocale(LC_ALL, "Russian");

    const std::string privateKeyFilename = "private_key_encrypted.txt";
    const std::string publicKeyFilename = "public_key.txt";
    const std::string pinHashFilename = "pin_hash.txt";

    bool keysExist = fileExists(privateKeyFilename) && fileExists(publicKeyFilename);

    std::string pin, pinHash;
    std::pair<std::string, std::string> keys;

    if (keysExist) {
        // Загрузка существующего хеша PIN-кода
        if (!fileExists(pinHashFilename)) {
            std::cerr << "Файл с хешем PIN-кода не найден. Пожалуйста, удалите ключи и повторите попытку." << std::endl;
            return 1;
        }

        std::ifstream pinHashFile(pinHashFilename);
        if (!pinHashFile.is_open()) {
            std::cerr << "Ошибка открытия файла с хешем PIN-кода." << std::endl;
            return 1;
        }
        std::getline(pinHashFile, pinHash);

        // Пользователь вводит PIN-код для проверки
        while (true) {
            pin = getPINFromUser(false);
            if (CryptoUtils::hashPIN(pin) == pinHash) {
                break;
            }
            std::cout << "Неверный PIN-код. Попробуйте снова." << std::endl;
        }
    } else {
        // Генерация нового PIN-кода
        pin = getPINFromUser(true);
        pinHash = CryptoUtils::hashPIN(pin);

        // Сохранение хеша PIN-кода
        std::ofstream pinHashFile(pinHashFilename);
        if (!pinHashFile.is_open()) {
            std::cerr << "Ошибка создания файла с хешем PIN-кода." << std::endl;
            return 1;
        }
        pinHashFile << pinHash;
    }

    if (keysExist) {
        std::cout << "Keys already exist. Loading existing keys..." << std::endl;

        // Загрузка зашифрованного приватного ключа
        std::ifstream privateKeyFile(privateKeyFilename);
        if (!privateKeyFile.is_open()) {
            std::cerr << "Error opening private key file." << std::endl;
            return 1;
        }
        std::stringstream privateKeyBuffer;
        privateKeyBuffer << privateKeyFile.rdbuf();
        std::string encryptedPrivateKey = privateKeyBuffer.str();
        privateKeyFile.close();

        // Загрузка публичного ключа
        std::ifstream publicKeyFile(publicKeyFilename);
        if (!publicKeyFile.is_open()) {
            std::cerr << "Error opening public key file." << std::endl;
            return 1;
        }
        std::stringstream publicKeyBuffer;
        publicKeyBuffer << publicKeyFile.rdbuf();
        std::string hexPublicKey = publicKeyBuffer.str();
        publicKeyFile.close();

        try {
            std::string decryptedPrivateKey = CryptoUtils::decryptPrivateKey(encryptedPrivateKey, pin);
            std::cout << "Decrypted Private Key: " << decryptedPrivateKey << std::endl;
            std::cout << "Public Key: " << hexPublicKey << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Error decrypting private key: " << e.what() << std::endl;
            return 1;
        }
    } else {
        std::cout << "No keys found. Generating new keys..." << std::endl;

        // Генерация новых ключей
        auto keys = CryptoUtils::generateECDSAKeys();
        const unsigned char* publicKeyData = reinterpret_cast<const unsigned char*>(keys.first.data());
        const unsigned char* privateKeyData = reinterpret_cast<const unsigned char*>(keys.second.data());

        // Преобразование ключей в шестнадцатеричный формат
        std::string hexPublicKey = Serialization::bytesToHex(publicKeyData, keys.first.size());
        std::string hexPrivateKey = Serialization::bytesToHex(privateKeyData, keys.second.size());

        // Генерация Node ID из публичного ключа
        std::string nodeID = CryptoUtils::generateIDFromPublicKey(hexPublicKey);
        std::cout << "Node ID (from public key): " << nodeID << std::endl;

        // Зашифровываем приватный ключ с использованием PIN-кода
        std::string encryptedPrivateKey = CryptoUtils::encryptPrivateKey(hexPrivateKey, pin);

        // Сохраняем зашифрованный приватный ключ и публичный ключ
        std::ofstream privateKeyFile(privateKeyFilename);
        if (privateKeyFile.is_open()) {
            privateKeyFile << encryptedPrivateKey;
            privateKeyFile.close();
        }

        std::ofstream publicKeyFile(publicKeyFilename);
        if (publicKeyFile.is_open()) {
            publicKeyFile << hexPublicKey;
            publicKeyFile.close();
        }

        std::cout << "Private Key Encrypted and Saved." << std::endl;
        std::cout << "Public Key Saved as Node ID." << std::endl;
    }



    auto session_keys = CryptoUtils::generateECDSAKeys();
    const unsigned char* publicKeyData = reinterpret_cast<const unsigned char*>(session_keys.first.data());
    const unsigned char* privateKeyData = reinterpret_cast<const unsigned char*>(session_keys.second.data());

    // Преобразуем ключи в шестнадцатеричный формат только для вывода
    std::string hexPublicSessionKey = Serialization::bytesToHex(publicKeyData, session_keys.first.size());
    std::string hexPrivateSessionKey = Serialization::bytesToHex(privateKeyData, session_keys.second.size());

    // Вывод публичного ключа в более читаемом виде
    std::cout << "\n\nPublic session Key:\n";
    for (size_t i = 0; i < hexPublicSessionKey.size(); i += 64) {
        std::cout << hexPublicSessionKey.substr(i, 64) << "\n";
    }
    std::cout << std::endl;

    // Вывод приватного ключа в более читаемом виде
    std::cout << "Private session Key:\n";
    for (size_t i = 0; i < hexPrivateSessionKey.size(); i += 64) {
        std::cout << hexPrivateSessionKey.substr(i, 64) << "\n";
    }
    std::cout << std::endl;


    // Продолжение работы программы...
    std::string reputationID = CryptoUtils::generateIDFromPublicKey(keys.first);
    std::cout << "Node Reputation ID (from public key): " << reputationID << std::endl;
    
    // Продолжение работы программы...
    std::string sessionID = CryptoUtils::generateIDFromPublicKey(session_keys.first);
    std::cout << "Node Session ID (from public key): " << sessionID << std::endl;

    Node node(reputationID, sessionID);
    NetworkManager nm;

    std::cout << "External IP: " << node.getExternalIPAddr() << std::endl;
    std::cout << "Port: " << node.getPort() << std::endl;

    std::string node_IP = node.getExternalIPAddr();
    int node_PORT = node.getPort();

    std::string mainNodeIP = "77.239.124.83";
    int mainNodePort = 5000;

    std::string stun_server = "77.239.124.83";
    uint16_t stun_port = 3479;

    std::string turn_server = "77.239.124.83";
    uint16_t turn_port = 3479;

    nm.findICECandidates(stun_server, stun_port, turn_server, turn_port);

    const auto& srflxCandidates = nm.getSrflxCandidates();
    std::cout << "All found srflx candidates:" << std::endl;
    for (const auto& candidate : srflxCandidates) {
        std::cout << candidate << std::endl;
    }

    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}