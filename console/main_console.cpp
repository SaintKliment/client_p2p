#include <iostream>
#include "../core/NetworkManager.h"
#include "../core/Node.h"
#include <locale>
#include <thread>
#include <chrono>
#include "../core/Crypto.h"
#include <sys/stat.h>
#include <boost/filesystem.hpp>
#include "../core/Serialization.h"
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

#define TOR_PROXY_HOST "127.0.0.1"
#define TOR_PROXY_PORT 9050



namespace asio = boost::asio;
using tcp = asio::ip::tcp;

void free_port(int port) {
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



class Contact {
private:
    std::string onion_address; // .onion адрес контакта
    std::unique_ptr<tcp::socket> socket; // Сокет для соединения

public:
    // Конструктор с указанием только .onion адреса
    Contact(const std::string& address) : onion_address(address), socket(nullptr) {}

    // Метод для получения .onion адреса
    std::string get_onion_address() const {
        return onion_address;
    }

    // Метод для подключения к узлу через SOCKS5-прокси
    bool connectToNode() {
        try {
            // Создаем io_context для обработки событий ввода-вывода
            asio::io_context ioc;

            // Настройка resolver для работы с SOCKS5
            tcp::resolver resolver(ioc);

            // Адрес SOCKS5 прокси (обычно локальный хост и порт 9050 или 9150)
            std::string socks_host = "127.0.0.1";
            uint16_t socks_port = 9050;

            // Настройка endpoint для SOCKS5 прокси
            tcp::endpoint socks_endpoint(asio::ip::make_address(socks_host), socks_port);

            // Список портов для попытки подключения
            std::vector<uint16_t> ports_to_try = {80, 443, 8080, 54321}; // Можно добавить другие порты

            for (auto port : ports_to_try) {
                try {
                     // Создаем TCP сокет
                socket = std::make_unique<tcp::socket>(ioc);

                // Устанавливаем соединение с SOCKS5 прокси
                socket->connect(socks_endpoint);

                // Формируем запрос для SOCKS5 подключения к .onion адресу
                std::string target_host = onion_address;

                // SOCKS5 handshake: аутентификация
                std::string auth_request = "\x05\x01\x00"; // Версия SOCKS5, один метод аутентификации (без авторизации)
                asio::write(*socket, asio::buffer(auth_request));

                // Читаем ответ от SOCKS5 прокси на handshake
                char auth_reply[2];
                size_t auth_bytes_transferred = socket->read_some(asio::buffer(auth_reply));
                if (auth_bytes_transferred < 2 || auth_reply[0] != '\x05' || auth_reply[1] != '\x00') {
                    std::cerr << "SOCKS5 authentication failed. Trying next port..." << std::endl;
                    continue;
                }

                // Формируем CONNECT запрос для SOCKS5
                std::string connect_request = "\x05\x01\x00"; // Версия SOCKS5, CONNECT команду, доменное имя
                connect_request += char(target_host.size());   // Длина имени хоста
                connect_request += target_host;                // Сам .onion адрес
                connect_request += char(port >> 8);            // Высший байт порта
                connect_request += char(port & 0xFF);          // Нижний байт порта

                // Отправляем CONNECT запрос на SOCKS5 прокси
                asio::write(*socket, asio::buffer(connect_request));

                // Читаем ответ от SOCKS5 прокси на CONNECT запрос
                char connect_reply[4];
                size_t connect_bytes_transferred = socket->read_some(asio::buffer(connect_reply));
                if (connect_bytes_transferred < 4 || connect_reply[0] != '\x05' || connect_reply[1] != '\x00') {
                    std::cerr << "SOCKS5 connection failed for " << onion_address << ":" << port << ". Trying next port..." << std::endl;
                    continue;
                }

                // Если всё прошло успешно
                std::cout << "Successfully connected to " << onion_address << ":" << port << std::endl;
                return true;

                } catch (std::exception& e) {
                    std::cerr << "Error connecting to " << onion_address << ":" << port << ": " << e.what() << ". Trying next port..." << std::endl;
                }
            }

            std::cerr << "Failed to connect to " << onion_address << " on all available ports." << std::endl;
            return false;

        } catch (std::exception& e) {
            std::cerr << "General error: " << e.what() << std::endl;
            return false;
        }
    }

    // Метод для отправки сообщения
    void send_message(const std::string& message) {
        if (!socket) {
            std::cerr << "Ошибка: не установлено соединение с узлом!" << std::endl;
            return;
        }

        try {
            // Отправляем сообщение через установленное соединение
            asio::write(*socket, asio::buffer(message + "\n"));
            std::cout << "Сообщение отправлено: " << message << std::endl;

            // Получаем ответ от узла
            char buffer[1024] = {0};
            size_t bytes_read = socket->read_some(asio::buffer(buffer, sizeof(buffer)));
            std::cout << "Ответ от узла (" << bytes_read << " байт): " << std::string(buffer, bytes_read) << std::endl;

        } catch (std::exception& e) {
            std::cerr << "Ошибка при отправке или получении сообщения: " << e.what() << std::endl;
        }
    }

    // Метод для закрытия соединения
    void disconnect() {
        if (socket) {
            try {
                socket->shutdown(tcp::socket::shutdown_both);
                socket->close();
                std::cout << "Соединение с " << onion_address << " закрыто." << std::endl;
            } catch (std::exception& e) {
                std::cerr << "Ошибка при закрытии соединения: " << e.what() << std::endl;
            }
            socket.reset(); // Очищаем указатель на сокет
        }
    }
};


// #define PORT 54321

void start_server(const std::string& local_port) {
    try {
        // Создаем io_context для обработки событий ввода-вывода
        asio::io_context ioc;

        // Настройка TCP acceptor для прослушивания локального порта
        tcp::acceptor acceptor(ioc, tcp::endpoint(tcp::v4(), std::stoi(local_port)));

        std::cout << "Сервер запущен. Ожидание подключений на локальном порту " << local_port << "..." << std::endl;

        while (true) {
            // Ждём входящее соединение
            tcp::socket socket(ioc);
            acceptor.accept(socket);

            // Читаем сообщение от клиента
            char buffer[1024] = {0};
            size_t bytes_read = asio::read(socket, asio::buffer(buffer), asio::transfer_at_least(1));
            std::string message(buffer, bytes_read);

            std::cout << "Получено сообщение: " << message << std::endl;

            // Отправляем ответ клиенту
            const std::string response = "Сообщение получено!";
            asio::write(socket, asio::buffer(response));

            // Закрываем соединение
            socket.shutdown(tcp::socket::shutdown_both);
            socket.close();
        }

    } catch (std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
    }
}


// Функция для запуска Tor
void start_tor(const char* tor_path) {
    // Создаём директории для данных Tor
    const char* data_dir = "./tor_data";
    const char* hidden_service_dir = "./hidden_service";
    mkdir(data_dir, 0700);
    mkdir(hidden_service_dir, 0700);

    // Конфигурация Tor
    std::string torrc_content = R"(
        SocksPort 9050
        DataDirectory ./tor_data
        Log notice file ./tor.log
        HiddenServiceDir ./hidden_service/
        HiddenServicePort 80 127.0.0.1:8080
        
        Log notice file ./tor.log
        Log info file ./tor_info.log
        Log debug file ./tor_debug.log

        Log warn file ./tor_warn.log
        Log err file ./tor_err.log
    )";

    // Записываем конфигурацию в файл
    const char* torrc_file = "./torrc";
    std::ofstream torrc(torrc_file);
    torrc << torrc_content;
    torrc.close();

    // Запускаем Tor как подпроцесс
    pid_t pid = fork();
    if (pid == 0) {
        // Дочерний процесс
        execl(tor_path, "tor", "-f", torrc_file, nullptr);
        // Если execl вернул управление, значит произошла ошибка
        std::cerr << "Ошибка запуска Tor: " << strerror(errno) << std::endl;
        exit(1);
    } else if (pid > 0) {
        // Родительский процесс
        std::cout << "Tor запущен с PID: " << pid << std::endl;
    } else {
        // Ошибка fork
        std::cerr << "Ошибка fork: " << strerror(errno) << std::endl;
        exit(1);
    }
}

// Функция для получения .onion адреса
std::string get_onion_address() {
    const char* hostname_file = "./hidden_service/hostname";
    std::ifstream file(hostname_file);
    if (!file.is_open()) {
        std::cerr << "Не удалось открыть файл hostname!" << std::endl;
        return "";
    }

    std::string onion_address;
    std::getline(file, onion_address);
    return onion_address;
}


void run_server() {
    std::string port = "8080";
    start_server(port);
}






namespace fs = boost::filesystem;

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

    std::string hexPublicMasterKey;
    std::string hexPrivateMasterKey;

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
            hexPublicMasterKey = hexPublicKey;
            hexPrivateMasterKey = decryptedPrivateKey;
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
        std::string reputationID = CryptoUtils::generateIDFromPublicKey(hexPublicKey);
        std::cout << "Node Reputation ID (from public key): " << reputationID << std::endl;

        hexPublicMasterKey = hexPublicKey;
        hexPrivateMasterKey = hexPrivateKey;

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


    // Продолжение работы программы...
    std::string reputationID = CryptoUtils::generateIDFromPublicKey(hexPrivateMasterKey);
    std::cout << "Node (private key): " << hexPrivateSessionKey << std::endl;
    std::cout << "Node Reputation ID (from private key): " << reputationID << std::endl;
    
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



    free_port(9050);

    const char* tor_path = "../bin/tor";

    // Запускаем Tor
    start_tor(tor_path);

    // Ждём, пока Tor создаст .onion адрес
    sleep(5); // Даём время для создания скрытого сервиса

    // Получаем .onion адрес
    std::string onion_address = get_onion_address();
    if (!onion_address.empty()) {
        std::cout << "Ваш .onion адрес: " << onion_address << std::endl;
    } else {
        std::cerr << "Не удалось сгенерировать .onion адрес!" << std::endl;
    }

    std::thread server_thread(run_server);

    sleep(8); 

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

            Contact& selected_contact = contacts[index - 1];
            if (!selected_contact.connectToNode()) { // Используем правильное имя метода
                std::cout << "Не удалось подключиться к контакту.\n";
                continue;
            }

            // Отправляем сообщение
            std::cout << "Введите сообщение: ";
            std::string message;
            std::cin.ignore(); // Очищаем буфер
            std::getline(std::cin, message);

            selected_contact.send_message(message);
            selected_contact.disconnect();
        } else if (choice == 3) {
            break;
        } else {
            std::cout << "Неверный выбор.\n";
        }
    }



    server_thread.join();





    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}