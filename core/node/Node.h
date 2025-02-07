#ifndef NODE_H
#define NODE_H

#include <string>
#include <cstdint>
#include "../crypto/Crypto.h" 

class Node {
public:
    Node();  

    std::string getExternalIPAddr();  
    
    std::string get_available_port();
    std::string getPort(); 
    uint16_t getIntPort(); 
    
    void setReputationID(const std::string& repID);
    void setSessionID(const std::string& sesID);
    std::string getReputationID() const;
    std::string getSessionID() const;

    std::string getRepId();
    std::string getSessionId();
    
    static void start_server(const std::string& local_port);
    static void run_server(std::string& port);
    
private:
    std::string ReputationID;
    std::string SessionID;
    
    std::string externalIP;  

    std::string local_port;


    std::string getExternalIP(); 
    static size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userp);  
};

#endif // NODE_H