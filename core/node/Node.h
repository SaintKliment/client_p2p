#ifndef NODE_H
#define NODE_H

#include <string>
#include <cstdint>
#include "../crypto/Crypto.h" 

class Node {
public:
    Node();  

    std::string get_available_port();
    std::string getPort(); 
    uint16_t getIntPort(); 
    
    void setReputationID(const std::string& repID);
    std::string getReputationID() const;

    void setSessionID(const std::string& sesID);
    std::string getSessionID() const;

    void setOnion(const std::string& onion);
    std::string getOnion() const;

    static void start_server(const std::string& local_port);
    
private:
    std::string ReputationID;
    std::string SessionID;
    
    std::string onion_addr;  

    std::string local_port;
};

#endif // NODE_H