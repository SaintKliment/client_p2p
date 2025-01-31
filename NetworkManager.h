#ifndef NETWORK_MANAGER_H
#define NETWORK_MANAGER_H

#include <string>
#include <vector>
#include <mutex>

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http.hpp>
#include <nlohmann/json.hpp>
#include <iostream>
#include <string>
#include <thread>

#include <curl/curl.h>

class NetworkManager {
public:
    NetworkManager();
    NetworkManager(const std::string& ip, int port); 

    void startServer(); 
    

    bool openPortUPnP(int port);
    void request_register(const std::string& node_ip, int node_port, const std::string& node_id, const std::string& superNode_ip, int superNode_port);
    void request_nodes(const std::string& node_ip, int node_port, const std::string& node_id, const std::string& superNode_ip, int superNode_port);

private:
    std::string externalIP;
    int port; 


    void handleClient(boost::asio::ip::tcp::socket socket);
    void startAccepting(boost::asio::ip::tcp::acceptor& acceptor, boost::asio::io_context& io_context);

};

#endif // NETWORK_MANAGER_H