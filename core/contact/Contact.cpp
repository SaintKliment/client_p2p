
#include <iostream>
#include <vector>
#include <iomanip>
#include <exception>
#include "Сontact.h"
#include <boost/asio.hpp>

using namespace boost::asio;
using namespace boost::asio::ip;


// Конструктор с указанием только .onion адреса
Contact::Contact(const std::string& address)
    : onion_address(address), socket(nullptr) {}

// Метод для получения .onion адреса
std::string Contact::get_onion_address() const {
    return onion_address;
}

// Метод для подключения к узлу через SOCKS5-прокси
bool Contact::connectToNode() {
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
        std::vector<uint16_t> ports_to_try = {8080, 54321, 80, 443}; // Можно добавить другие порты

        for (auto port : ports_to_try) {
            try {
                // Создаем TCP сокет
                socket = std::make_unique<tcp::socket>(ioc);
                std::cout << "TCP socket created." << std::endl;

                // Устанавливаем соединение с SOCKS5 прокси
                std::cout << "Attempting to connect to SOCKS5 proxy at " << socks_host << ":" << socks_port << "..." << std::endl;
                socket->connect(socks_endpoint);
                std::cout << "Successfully connected to SOCKS5 proxy." << std::endl;

                // Формируем запрос для SOCKS5 подключения к .onion адресу
                std::string target_host = onion_address;

                // SOCKS5 handshake: аутентификация
                std::cout << "Performing SOCKS5 authentication..." << std::endl;
                std::string auth_request = "\x05\x01\x00"; // Версия SOCKS5, один метод аутентификации (без авторизации)
                asio::write(*socket, asio::buffer(auth_request));
                std::cout << "SOCKS5 authentication request sent." << std::endl;

                // Читаем ответ от SOCKS5 прокси на handshake
                char auth_reply[2];
                size_t auth_bytes_transferred = 0;
                try {
                    auth_bytes_transferred = socket->read_some(asio::buffer(auth_reply));
                    std::cout << "Received SOCKS5 authentication response (" << auth_bytes_transferred << " bytes): ";
                    for (size_t i = 0; i < auth_bytes_transferred; ++i) {
                        std::cout << "\\x" << std::hex << (unsigned int)(unsigned char)auth_reply[i];
                    }
                    std::cout << std::dec << "." << std::endl;
                } catch (std::exception& e) {
                    std::cerr << "Error reading SOCKS5 authentication response: " << e.what() << ". Trying next port..." << std::endl;
                    continue;
                }

                if (auth_bytes_transferred < 2 || auth_reply[0] != '\x05' || auth_reply[1] != '\x00') {
                    std::cerr << "SOCKS5 authentication failed. Expected \\x05\\x00, but received: ";
                    for (size_t i = 0; i < auth_bytes_transferred; ++i) {
                        std::cerr << "\\x" << std::hex << (unsigned int)(unsigned char)auth_reply[i];
                    }
                    std::cerr << std::dec << ". Trying next port..." << std::endl;
                    continue;
                }
                std::cout << "SOCKS5 authentication successful." << std::endl;

                // Формируем CONNECT запрос для SOCKS5
                std::cout << "Forming CONNECT request for " << target_host << ":" << port << "..." << std::endl;
                std::string connect_request = "\x05\x01\x00"; // Версия SOCKS5, CONNECT команду, доменное имя
                connect_request += char(target_host.size());   // Длина имени хоста
                connect_request += target_host;                // Сам .onion адрес
                connect_request += char(port >> 8);            // Высший байт порта
                connect_request += char(port & 0xFF);          // Нижний байт порта

                // Отправляем CONNECT запрос на SOCKS5 прокси
                std::cout << "Sending CONNECT request to SOCKS5 proxy..." << std::endl;
                asio::write(*socket, asio::buffer(connect_request));
                std::cout << "CONNECT request sent." << std::endl;

                // Читаем ответ от SOCKS5 прокси на CONNECT запрос
                char connect_reply[4];
                size_t connect_bytes_transferred = 0;
                try {
                    connect_bytes_transferred = socket->read_some(asio::buffer(connect_reply));
                    std::cout << "Received CONNECT response (" << connect_bytes_transferred << " bytes): ";
                    for (size_t i = 0; i < connect_bytes_transferred; ++i) {
                        std::cout << "\\x" << std::hex << (unsigned int)(unsigned char)connect_reply[i];
                    }
                    std::cout << std::dec << "." << std::endl;
                } catch (std::exception& e) {
                    std::cerr << "Error reading CONNECT response: " << e.what() << ". Trying next port..." << std::endl;
                    continue;
                }

                if (connect_bytes_transferred < 4 || connect_reply[0] != '\x05' || connect_reply[1] != '\x00') {
                    std::cerr << "SOCKS5 connection failed for " << onion_address << ":" << port << ". Expected \\x05\\x00, but received: ";
                    for (size_t i = 0; i < connect_bytes_transferred; ++i) {
                        std::cerr << "\\x" << std::hex << (unsigned int)(unsigned char)connect_reply[i];
                    }
                    std::cerr << std::dec << ". Trying next port..." << std::endl;
                    continue;
                }

                // Если всё прошло успешно
                std::cout << "Successfully connected to " << onion_address << ":" << port << std::endl;


                std::string message = "пиривет";
                const char* buffer = message.c_str();
                size_t length = message.size();
                // ssize_t bytes_sent = send(socket_fd, buffer, length, 0);
                size_t bytes_sent = asio::write(*socket, asio::buffer(buffer, length));
                
                if (bytes_sent == -1) {
                    std::cerr << "Failed to send message" << std::endl;
                    } else {
                    std::cout << "Sent " << bytes_sent << " bytes: " << message << std::endl;
                }


    
                return true;
            } catch (std::exception& e) {
                std::cerr << "Error during connection attempt to " << onion_address << ":" << port << ": " << e.what() << ". Trying next port..." << std::endl;
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
void Contact::send_message(const std::string& message) {
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
void Contact::disconnect() {
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