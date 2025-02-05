#include "Node.h"
#include <iostream>
#include <curl/curl.h>
#include <boost/asio.hpp>
#include <sstream>
#include <string>
#include <thread> 


namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using boost::asio::ip::tcp;

Node::Node(const std::string& repID, const std::string& sesID) {
    ReputationID = repID;
    SessionID = sesID;
    
    externalIP = getExternalIP();
    port = 54321;
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

int Node::getPort() {
    return port;
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



void Node::run_server(std::string& port) {
    std::thread server_thread(start_server , std::ref(port));
 
    if (server_thread.joinable()) {
            server_thread.join();
        }
}