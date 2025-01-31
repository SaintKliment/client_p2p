#include <iostream>
#include "NetworkManager.h"
#include "Node.h"
#include <locale>
#include <iostream>
#include <thread>
#include <chrono>
#include "Crypto.h"

int main() {
    setlocale(LC_ALL, "Russian");

auto keys = CryptoUtils::generateECDSAKeys();
    const unsigned char* publicKeyData = reinterpret_cast<const unsigned char*>(keys.first.data());
    const unsigned char* privateKeyData = reinterpret_cast<const unsigned char*>(keys.second.data());

    // Преобразуем ключи в шестнадцатеричный формат только для вывода
    std::string hexPublicKey = CryptoUtils::toHex(publicKeyData, keys.first.size());
    std::string hexPrivateKey = CryptoUtils::toHex(privateKeyData, keys.second.size());

    // Вывод публичного ключа в более читаемом виде
    std::cout << "Public Key:\n";
    for (size_t i = 0; i < hexPublicKey.size(); i += 64) {
        std::cout << hexPublicKey.substr(i, 64) << "\n";
    }
    std::cout << std::endl;

    // Вывод приватного ключа в более читаемом виде
    std::cout << "Private Key:\n";
    for (size_t i = 0; i < hexPrivateKey.size(); i += 64) {
        std::cout << hexPrivateKey.substr(i, 64) << "\n";
    }
    std::cout << std::endl;

     // Генерация и вывод Node ID из публичного ключа
    std::string nodeID = CryptoUtils::generateIDFromPublicKey(keys.first);
    std::cout << "Node ID (from public key): " << nodeID << std::endl;


    Node node(nodeID);
    NetworkManager networkManager;

    std::cout << "External IP: " << node.getExternalIPAddr() << std::endl;
    std::cout << "Port: " << node.getPort() << std::endl;


    std::string node_IP = node.getExternalIPAddr();
    int node_PORT = node.getPort();


    std::string mainNodeIP = "77.239.124.83";
    int mainNodePort = 5000;

    networkManager.request_register(node_IP, node_PORT, nodeID, mainNodeIP, mainNodePort);
    //networkManager.startServer();

    networkManager.request_nodes(node_IP, node_PORT, nodeID, mainNodeIP, mainNodePort);

    std::string stun_server = "77.239.124.83";
    int stun_port = 3479;
    
    std::string turn_server = "77.239.124.83";
    uint16_t turn_port = 3479;

    

    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}