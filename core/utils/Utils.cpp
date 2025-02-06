#include "./Utils.h"
#include "../crypto/Crypto.h"
#include "../serialization/Serialization.h"
#include "../../console/UserInputCollector.h"
#include <boost/filesystem.hpp>
#include <iostream>
#include <sstream> // для std::stringstream

namespace fs = boost::filesystem;


bool Utils::fileExists(const std::string& filename) {
    return fs::exists(filename);
}


void Utils::free_port(int port) {
    // Команда для поиска процесса, использующего порт
    std::string command = "sudo lsof -i:" + std::to_string(port) + " -t";
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        std::cerr << "Ошибка при выполнении команды lsof!" << std::endl;
        return;
    }

    char buffer[128];
    std::string result = "";
    while (!feof(pipe)) {
        if (fgets(buffer, 128, pipe) != nullptr) {
            result += buffer;
        }
    }
    pclose(pipe);

    // Если найден PID, завершаем процесс
    if (!result.empty()) {
        int pid = std::stoi(result);
        std::cout << "Порт " << port << " занят процессом с PID: " << pid << ". Завершаем процесс..." << std::endl;
        std::string kill_command = "sudo kill -9 " + std::to_string(pid);
        system(kill_command.c_str());
    } else {
        std::cout << "Порт " << port << " свободен." << std::endl;
    }
}



void Utils::login(const std::string& privateKeyFilename,
                const std::string& publicKeyFilename,
                const std::string& pinHashFilename,
                std::string& hexPublicMasterKey,
                std::string& hexPrivateMasterKey) 
{
    bool keysExist = Utils::fileExists(privateKeyFilename) && Utils::fileExists(publicKeyFilename);
    std::string pin, pinHash;

    if (keysExist) {
        // Загрузка существующего хеша PIN-кода
        if (!Utils::fileExists(pinHashFilename)) {
            throw std::runtime_error("Файл с хешем PIN-кода не найден. Пожалуйста, удалите ключи и повторите попытку.");
        }

        std::ifstream pinHashFile(pinHashFilename);
        if (!pinHashFile.is_open()) {
            throw std::runtime_error("Ошибка открытия файла с хешем PIN-кода.");
        }
        std::getline(pinHashFile, pinHash);

        // Проверка PIN-кода
        while (true) {
            pin = UserInputCollector::getPINFromUser(false);
            if (CryptoUtils::hashPIN(pin) == pinHash) break;
            std::cout << "Неверный PIN-код. Попробуйте снова." << std::endl;
        }
    } else {
        // Генерация нового PIN-кода
        pin = UserInputCollector::getPINFromUser(true);
        pinHash = CryptoUtils::hashPIN(pin);

        // Сохранение хеша PIN-кода
        std::ofstream pinHashFile(pinHashFilename);
        if (!pinHashFile.is_open()) {
            throw std::runtime_error("Ошибка создания файла с хешем PIN-кода.");
        }
        pinHashFile << pinHash;
    }

    if (keysExist) {
        // Загрузка существующих ключей
        std::ifstream privateKeyFile(privateKeyFilename);
        if (!privateKeyFile.is_open()) {
            throw std::runtime_error("Error opening private key file.");
        }

        std::stringstream privateKeyBuffer;
        privateKeyBuffer << privateKeyFile.rdbuf();
        std::string encryptedPrivateKey = privateKeyBuffer.str();

        std::ifstream publicKeyFile(publicKeyFilename);
        if (!publicKeyFile.is_open()) {
            throw std::runtime_error("Error opening public key file.");
        }

        std::stringstream publicKeyBuffer;
        publicKeyBuffer << publicKeyFile.rdbuf();
        std::string hexPublicKey = publicKeyBuffer.str();

        try {
            std::string decryptedPrivateKey = CryptoUtils::decryptPrivateKey(encryptedPrivateKey, pin);
            hexPublicMasterKey = hexPublicKey;
            hexPrivateMasterKey = decryptedPrivateKey;
        } catch (const std::exception& e) {
            throw std::runtime_error("Error decrypting private key: " + std::string(e.what()));
        }
    } else {
    std::cout << "No keys found. Generating new keys..." << std::endl;

    // Генерация новых ключей
    auto keys = CryptoUtils::generateECDSAKeys();
    
    // Явное преобразование типов
    const unsigned char* publicKeyData = 
        reinterpret_cast<const unsigned char*>(keys.first.data());
    const unsigned char* privateKeyData = 
        reinterpret_cast<const unsigned char*>(keys.second.data());

    // Преобразование в hex
    std::string hexPublicKey = Serialization::bytesToHex(
        publicKeyData, 
        keys.first.size()
    );
    std::string hexPrivateKey = Serialization::bytesToHex(
        privateKeyData, 
        keys.second.size()
    );

}}


std::pair<std::string, std::string> Utils::generateSessionKeys() {
    // Генерация сессионных ключей
    auto session_keys = CryptoUtils::generateECDSAKeys();

    // Преобразование ключей в указатели unsigned char*
    const unsigned char* publicKeyData = reinterpret_cast<const unsigned char*>(session_keys.first.data());
    const unsigned char* privateKeyData = reinterpret_cast<const unsigned char*>(session_keys.second.data());

    // Преобразование ключей в шестнадцатеричный формат
    std::string hexPublicSessionKey = Serialization::bytesToHex(publicKeyData, session_keys.first.size());
    std::string hexPrivateSessionKey = Serialization::bytesToHex(privateKeyData, session_keys.second.size());

    // Возвращаем пару строк
    return {hexPublicSessionKey, hexPrivateSessionKey};
}