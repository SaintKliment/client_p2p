
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


bool Contact::connectToNode(boost::asio::io_context& ioc) {
    try {

        if (!socket) {
            socket = std::make_unique<boost::asio::ip::tcp::socket>(ioc);
        }

        // Адрес SOCKS5 прокси (локальный Tor-прокси)
        std::string socks_host = "127.0.0.1";
        uint16_t socks_port = 9050;

        uint16_t onion_port = 80;

        // Настройка endpoint для SOCKS5 прокси
        boost::asio::ip::tcp::endpoint socks_endpoint(boost::asio::ip::make_address(socks_host), socks_port);

        // Создаем сокет для подключения к SOCKS5 прокси
        boost::asio::ip::tcp::socket socket(ioc);

        // Подключаемся к SOCKS5 прокси
        socket.connect(socks_endpoint);
        std::cout << "Connected to SOCKS5 proxy at " << socks_host << ":" << socks_port << std::endl;

        // Выполняем SOCKS5 handshake
        {
            // Шаг 1: Отправляем приветствие (версия SOCKS5, методы аутентификации)
            std::vector<uint8_t> handshake_request = {0x05, 0x01, 0x00}; // Версия 5, 1 метод аутентификации (0x00 — без аутентификации)
            boost::asio::write(socket, boost::asio::buffer(handshake_request));

            // Шаг 2: Получаем ответ от сервера
            std::vector<uint8_t> response(2);
            boost::asio::read(socket, boost::asio::buffer(response));

            if (response[0] != 0x05 || response[1] != 0x00) {
                throw std::runtime_error("SOCKS5 handshake failed: server does not support no authentication");
            }
            std::cout << "SOCKS5 handshake successful." << std::endl;
        }

        // Выполняем CONNECT-запрос к .onion-адресу
        {
            // Шаг 3: Формируем CONNECT-запрос
            std::vector<uint8_t> request;
            request.push_back(0x05); // Версия 5
            request.push_back(0x01); // Команда CONNECT (0x01)
            request.push_back(0x00); // Зарезервированный байт (0x00)
            request.push_back(0x03); // Тип адреса: доменное имя (0x03)
            request.push_back(static_cast<uint8_t>(onion_address.size())); // Длина доменного имени
            request.insert(request.end(), onion_address.begin(), onion_address.end()); // Доменное имя
            request.push_back((onion_port >> 8) & 0xFF); // Старший байт порта
            request.push_back(onion_port & 0xFF);       // Младший байт порта

            // Отправляем CONNECT-запрос
            boost::asio::write(socket, boost::asio::buffer(request));

            // Шаг 4: Получаем ответ от сервера
            std::vector<uint8_t> response(10);
            boost::asio::read(socket, boost::asio::buffer(response));

            if (response[0] != 0x05) {
                throw std::runtime_error("Invalid SOCKS5 response version");
            }

            uint8_t reply_code = response[1];
            if (reply_code != 0x00) {
                throw std::runtime_error("SOCKS5 connection failed: error code " + std::to_string(reply_code));
            }
            std::cout << "SOCKS5 CONNECT request successful. Connected to " << onion_address << ":" << onion_port << std::endl;
        }

        // Здесь можно добавить логику для отправки данных или получения ответа от .onion-узла
        return true; // Успешное подключение
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return false; // Ошибка подключения
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