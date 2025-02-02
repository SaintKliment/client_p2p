#ifndef NODE_H
#define NODE_H

#include <string>
#include "Crypto.h" 

class Node {
public:
    Node(const std::string& repID, const std::string& sesID);  
    std::string getExternalIPAddr();  
    int getPort();  
    std::string getRepId();
    std::string getSessionId();

private:
    std::string ReputationID;
    std::string SessionID;
    
    std::string externalIP;  
    int port;  


    std::string getExternalIP(); 
    static size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userp);  
};

#endif // NODE_H