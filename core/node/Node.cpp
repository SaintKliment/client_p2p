#include "Node.h"
#include <stdexcept> // Для std::runtime_error
#include <iostream>
#include <curl/curl.h>
#include <boost/asio.hpp>
#include <sstream>
#include <string>
#include <thread> 
#include <cstdint>

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using boost::asio::ip::tcp;

Node::Node() {
    ReputationID = ""; 
    SessionID = "";
    
    externalIP = getExternalIP();
    local_port = get_available_port();
}

void Node::setReputationID(const std::string& repID) {
    ReputationID = repID;
}

void Node::setSessionID(const std::string& sesID) {
    SessionID = sesID;
}

std::string Node::getReputationID() const {
    return ReputationID;
}

std::string Node::getSessionID() const {
    return SessionID;
}

std::string Node::getExternalIP() {
    CURL* curl;
    CURLcode res;
    std::string ip;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://api.ipify.org/");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ip);
        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
        }

        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();

    return ip;
}

std::string Node::getExternalIPAddr() {
    return externalIP;
}

std::string Node::getPort() {
    return Node::local_port;
}

uint16_t Node::getIntPort(){
try {
            uint16_t port = static_cast<uint16_t>(std::stoul(this->local_port)); // Преобразуем строку в unsigned long, затем в uint16_t
            if (port > 0 && port <= 65535) { // Проверяем, что порт находится в допустимом диапазоне
                return port;
            } else {
                throw std::invalid_argument("Port is out of range (0-65535).");
            }
        } catch (const std::invalid_argument& e) {
            std::cerr << "Error: Invalid port value. " << e.what() << std::endl;
            throw; // Перебрасываем исключение дальше
        } catch (const std::out_of_range& e) {
            std::cerr << "Error: Port value out of range. " << e.what() << std::endl;
            throw; // Перебрасываем исключение дальше
        }
}

std::string Node::getRepId() {
    return ReputationID;
}

std::string Node::getSessionId() {
    return SessionID;
}


size_t Node::writeCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}


void Node::start_server(const std::string& local_port) {
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

            std::cout << "\nПолучено сообщение: " << message << std::endl;

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

void Node::run_server(std::string& port) {
    std::thread server_thread(start_server , std::ref(port));
 
    if (server_thread.joinable()) {
        server_thread.detach(); // Отсоединяем поток, чтобы он работал независимо
    }
}

std::string Node::get_available_port() {
    boost::asio::io_context io_context;

    // Начинаем проверку с порта 8080
    for (uint16_t port = 8080; port <= 65535; ++port) {
        try {
            // Создаём acceptor для проверки порта
            boost::asio::ip::tcp::acceptor acceptor(io_context, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port));

            // Порт свободен, выводим сообщение и возвращаем его
            std::cout << "Port " << port << " is available and can be used." << std::endl;
            return std::to_string(port);
        } catch (const std::exception& e) {
            // Если порт занят, продолжаем проверку следующего порта
            continue;
        }
    }

    // Если не нашли свободный порт, выбрасываем исключение
    throw std::runtime_error("No available ports in the range 8080-65535.");
}
