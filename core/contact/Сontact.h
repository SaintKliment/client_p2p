#ifndef CONTACT_H
#define CONTACT_H

#include <string>
#include <memory>
#include <boost/asio.hpp>

namespace asio = boost::asio;
namespace ip = boost::asio::ip;


class Contact {
private:
    std::string onion_address; // .onion адрес контакта
    std::unique_ptr<asio::ip::tcp::socket> socket; // Сокет для соединения

public:
    // Конструктор с указанием только .onion адреса
    Contact(const std::string& address);

    // Метод для получения .onion адреса
    std::string get_onion_address() const;

    // Метод для подключения к узлу через SOCKS5-прокси
    bool connectToNode();

    // Метод для отправки сообщения
    void send_message(const std::string& message);

    // Метод для закрытия соединения
    void disconnect();
};

#endif // CONTACT_H