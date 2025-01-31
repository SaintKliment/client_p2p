#include "Node.h"
#include <iostream>
#include <curl/curl.h>
#include <boost/asio.hpp>
#include <sstream>
#include <string>

using boost::asio::ip::tcp;

Node::Node(const std::string& nodeID) {
    id = nodeID;
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

std::string Node::getId() {
    return id;
}


size_t Node::writeCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

