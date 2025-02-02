#ifndef NETWORK_MANAGER_H
#define NETWORK_MANAGER_H

#include <string>
#include <vector>
#include <mutex>

#include <nice/nice.h>


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
    
    ~NetworkManager();

    void findICECandidates(const std::string& stunServer, uint16_t stunPort, const std::string& turnServer, uint16_t turnPort);
    
    const std::vector<std::string>& getCandidates() const;
    std::vector<std::string> getSrflxCandidates() const;

    bool openPortUPnP(int port);
    void request_register(const std::string& node_ip, int node_port, const std::string& node_id, const std::string& superNode_ip, int superNode_port);
    void request_nodes(const std::string& node_ip, int node_port, const std::string& node_id, const std::string& superNode_ip, int superNode_port);

private:
    std::string externalIP;
    int port; 
    std::vector<std::string> candidates;
    NiceAgent* agent;
    GMainLoop* main_loop;

    static void candidateGatheringDone(NiceAgent *agent, guint stream_id, gpointer user_data);

};
#endif // NETWORK_MANAGER_H