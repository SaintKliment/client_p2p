#include "NetworkManager.h"
#include <iostream>
#include <boost/asio.hpp>
#include <thread>
#include <array>

#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>

NetworkManager::NetworkManager() {  }

NetworkManager::NetworkManager(const std::string& ip, int port)
    : externalIP(ip), port(port) {}


bool  NetworkManager::openPortUPnP(int port) {
    struct UPNPDev* devlist = nullptr;
    struct UPNPUrls urls;
    struct IGDdatas data;
    char externalIP[40];

    int error = 0;

    // upnpDiscover 
    devlist = upnpDiscover(2000,   
        NULL,    
        NULL,    
        0,        
        0,       
        255,     
        &error); 

    if (devlist == NULL) {
        std::cerr << "������ ��� ������ UPnP ���������: " << error << std::endl;
        return false;
    }
    else {
        std::cout << "UPnP ���������� �������!" << std::endl;
    }


    if (UPNP_GetValidIGD(devlist, &urls, &data, externalIP, sizeof(externalIP)) != 1) {
        std::cerr << "Failed to find a valid IGD." << std::endl;
        freeUPNPDevlist(devlist);
        return false;
    }

    std::cout << "External IP Address: " << externalIP << std::endl;


    const char* protocol = "TCP";    
    const char* description = "Bitcoin Node";
    char portStr[6];
    snprintf(portStr, sizeof(portStr), "%d", port);

    int result = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype,
        portStr, portStr, externalIP, description, protocol, NULL, "0");
    std::cout << result << std::endl;
    
    
    if (result == UPNPCOMMAND_SUCCESS) {
        std::cout << "Port " << port << " opened successfully." << std::endl;
        freeUPNPDevlist(devlist);
        FreeUPNPUrls(&urls);
        return true;
    }
    else {
        std::cerr << "Failed to open port: " << strupnperror(result) << std::endl;
        freeUPNPDevlist(devlist);
        FreeUPNPUrls(&urls);
        return false;
    }
}

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

void NetworkManager::request_register(const std::string& node_ip, int node_port, const std::string& node_id, const std::string& superNode_ip, int superNode_port) {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;


    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl) {

        std::string url = "http://" + superNode_ip + ":" + std::to_string(superNode_port) + "/register";


        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());


        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);


        std::string jsonData = "{\"ip\": \"" + node_ip + "\", \"port\": " + std::to_string(node_port) + ", \"id\": \"" + node_id + "\"}";


        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonData.c_str());


        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);


        res = curl_easy_perform(curl);


        if (res != CURLE_OK) {
            std::cerr << "cURL error: " << curl_easy_strerror(res) << std::endl;
        }
        else {

            std::cout << "Registration attempt: " << readBuffer << std::endl;
        }


        curl_slist_free_all(headers);


        curl_easy_cleanup(curl);
    }


    curl_global_cleanup();
}


void NetworkManager::request_nodes(const std::string& node_ip, int node_port, const std::string& node_id, const std::string& superNode_ip, int superNode_port) {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;


    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl) {

        std::string url = "http://" + superNode_ip + ":" + std::to_string(superNode_port) + "/nodes";


        url += "?id=" + node_id;


        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());


        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);


        res = curl_easy_perform(curl);


        if (res != CURLE_OK) {
            std::cerr << "cURL error: " << curl_easy_strerror(res) << std::endl;
        }
        else {

            std::cout << "List of available nodes: " << readBuffer << std::endl;
        }


        curl_easy_cleanup(curl);
    }


    curl_global_cleanup();
}



void NetworkManager::startServer() {
    try {
        
        /*if (!openPortUPnP(port)) {
            std::cerr << "UPnP port forwarding failed. Server will not be accessible externally." << std::endl;
        }*/

        boost::asio::io_context io_context;

        
        boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::address::from_string("0.0.0.0"), port);
        boost::asio::ip::tcp::acceptor acceptor(io_context, endpoint);

        std::cout << "Server is listening on port " << port << std::endl;

        
        startAccepting(acceptor, io_context);

        io_context.run();
    }
    catch (const std::exception& e) {
        std::cerr << "Error in startServer: " << e.what() << std::endl;
    }
}


void NetworkManager::startAccepting(boost::asio::ip::tcp::acceptor& acceptor, boost::asio::io_context& io_context) {
    auto socket = std::make_shared<boost::asio::ip::tcp::socket>(io_context);

    acceptor.async_accept(*socket, [this, socket, &acceptor, &io_context](const boost::system::error_code& error) {
        if (!error) {
            std::cout << "New client connected!" << std::endl;
            std::thread(&NetworkManager::handleClient, this, std::move(*socket)).detach();
        }
        else {
            std::cerr << "Accept failed: " << error.message() << std::endl;
        }

        startAccepting(acceptor, io_context);
        });
}



void NetworkManager::handleClient(boost::asio::ip::tcp::socket socket) {
    try {
        std::array<char, 128> buffer;


        std::size_t len = socket.read_some(boost::asio::buffer(buffer));
        std::cout << "Received message: " << std::string(buffer.data(), len) << std::endl;

        std::string message = "Hello from server!";
        boost::asio::write(socket, boost::asio::buffer(message));

        socket.close();
    }
    catch (const std::exception& e) {
        std::cerr << "Error in handleClient: " << e.what() << std::endl;
    }
}