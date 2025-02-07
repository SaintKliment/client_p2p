#include <iostream>
#include "../core/nm/NetworkManager.h"
#include "../core/node/Node.h"
#include "../core/serialization/Serialization.h"
#include <locale>
#include <thread>
#include <chrono>
#include <sys/stat.h>
#include <iomanip>
#include <sstream>
#include <openssl/evp.h>


#include <cstdlib>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <limits.h> // Для PATH_MAX
#include <fstream> 


#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/version.hpp>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <netdb.h>
#include <functional> 
#include <../core/utils/Utils.h>
#include <../core/contact/Сontact.h>
#include <../core/tor_work/Torw.cpp>
#include <../core/thread_pool/ThreadPool.h>


int main() {
    setlocale(LC_ALL, "Russian");
    ThreadPool thread_pool;

    Node node;
    std::string server_port= node.getPort();

    std::string thread_name_1 = "server_on_port_" + server_port;
    thread_pool.add_task(thread_name_1, std::bind(&Node::start_server, std::cref(server_port)));

    std::string thread_name_2 = "tor";
    Torw tor_instance;
    thread_pool.add_task(
    thread_name_2,
    std::bind(&Torw::check_tor_before_start, server_port));
    // Torw::check_tor_before_start(server_port);

    const std::string privateKeyFilename = "private_key_encrypted.txt";
    const std::string publicKeyFilename = "public_key.txt";
    const std::string pinHashFilename = "pin_hash.txt";

    std::string hexPublicMasterKey;
    std::string hexPrivateMasterKey;

    try {
    Utils::login(privateKeyFilename, publicKeyFilename, pinHashFilename, hexPublicMasterKey, hexPrivateMasterKey);
        } 
    catch (const std::exception& e) {
    std::cerr << "Ошибка: " << e.what() << std::endl;
    }
    

    auto [hexPublicSessionKey, hexPrivateSessionKey] = Utils::generateSessionKeys();


    std::string reputationID = CryptoUtils::generateIDFromPublicKey(hexPrivateMasterKey);
    std::cout << "Node Reputation ID (from private key): " << reputationID << std::endl;
    
    std::string sessionID = CryptoUtils::generateIDFromPublicKey(hexPublicSessionKey);
    std::cout << "Node Session ID (from hex public key): " << sessionID << std::endl;
    std::cout << "Node Session (hex private key): " << hexPrivateSessionKey << std::endl;

    node.setReputationID(reputationID);
    node.setSessionID(sessionID);
    

    std::string onion_address = tor_instance.get_onion_address();
    if (!onion_address.empty()) {
        std::cout << "Ваш .onion адрес: " << onion_address << std::endl;
        node.setOnion(onion_address);
    } else {
        std::cerr << "Не удалось сгенерировать .onion адрес!" << std::endl;
    }

    
    
    std::vector<Contact> contacts;

    while (true) {
        std::cout << "1. Добавить контакт\n2. Отправить сообщение\n3. Выйти\nВыберите действие: ";
        int choice;
        std::cin >> choice;

        if (choice == 1) {
            std::cout << "Введите .onion адрес контакта: ";
            std::string onion_address;
            std::cin >> onion_address;
            contacts.emplace_back(onion_address);
            std::cout << "Контакт добавлен.\n";
        } else if (choice == 2) {
            if (contacts.empty()) {
                std::cout << "Нет доступных контактов.\n";
                continue;
            }

            // Выводим пронумерованный список контактов
            std::cout << "Список контактов:\n";
            for (size_t i = 0; i < contacts.size(); ++i) {
                std::cout << i + 1 << ". " << contacts[i].get_onion_address() << "\n";
            }

            std::cout << "Выберите контакт (номер): ";
            int index;
            std::cin >> index;

            if (index < 1 || index > static_cast<int>(contacts.size())) {
                std::cout << "Неверный номер контакта.\n";
                continue;
            }

            boost::asio::io_context ioc;
            Contact& selected_contact = contacts[index - 1];
            if (!selected_contact.connectToNode(ioc)) { // Используем правильное имя метода
                std::cout << "Не удалось подключиться к контакту.\n";
                continue;
            }

            // Отправляем сообщение
            std::cout << "Введите сообщение: ";
            std::string message;
            std::cin.ignore(); // Очищаем буфер
            std::getline(std::cin, message);

            selected_contact.send_message(message);
            // selected_contact.disconnect()
        } else if (choice == 3) {
            break;
        } else {
            std::cout << "Неверный выбор.\n";
        }
    }

    return 0;
}