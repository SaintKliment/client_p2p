#include "NetworkManager.h"
#include <iostream>
#include <boost/asio.hpp>
#include <thread>
#include <array>

#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>

#include <glib.h>
#include <cstring> // Для memset
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>


NetworkManager::NetworkManager() 
    : agent(nullptr), main_loop(g_main_loop_new(NULL, FALSE)) {}


NetworkManager::NetworkManager(const std::string& ip, int port)
    : externalIP(ip), port(port) {}

NetworkManager::~NetworkManager() {
    if (agent) {
        g_object_unref(agent);
    }
    if (main_loop) {
        g_main_loop_unref(main_loop);
    }
}


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

    // char lanAddress[64];
    // int lanAddressSize = sizeof(lanAddress); lanAddress, lanAddressSize,

    if (UPNP_GetValidIGD(devlist, &urls, &data, externalIP,  sizeof(externalIP)) != 1) {
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


void NetworkManager::findICECandidates(const std::string& stunServer, uint16_t stunPort, const std::string& turnServer, uint16_t turnPort) {
    if (agent) {
        g_object_unref(agent);
    }
    if (main_loop) {
        g_main_loop_unref(main_loop);
    }

    main_loop = g_main_loop_new(NULL, FALSE);
    agent = nice_agent_new(g_main_loop_get_context(main_loop), NICE_COMPATIBILITY_RFC5245);
    if (!agent) {
        std::cerr << "Failed to create NICE agent" << std::endl;
        return;
    }

    // Настройка STUN сервера
    g_object_set(G_OBJECT(agent), "stun-server", stunServer.c_str(), NULL);
    g_object_set(G_OBJECT(agent), "stun-server-port", stunPort, NULL);

    // Настройка TURN сервера
    guint stream_id = nice_agent_add_stream(agent, 1);
    if (stream_id == 0) {
        std::cerr << "Failed to add stream" << std::endl;
        return;
    }

    if (!nice_agent_set_relay_info(agent, stream_id, 1,
                                   turnServer.c_str(), turnPort,
                                   "username", "password", NICE_RELAY_TYPE_TURN_UDP)) {
        std::cerr << "Failed to set TURN relay info" << std::endl;
    }

    // Сбор кандидатов
    nice_agent_gather_candidates(agent, stream_id);

    // Подключение сигнала завершения сбора кандидатов
    g_signal_connect(agent, "candidate-gathering-done", G_CALLBACK(candidateGatheringDone), this);

    if (main_loop) {
        g_main_loop_run(main_loop);
    }
}


const char* getCandidateTypeName(NiceCandidateType type) {
    switch (type) {
        case NICE_CANDIDATE_TYPE_HOST:
            return "host";
        case NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE:
            return "srflx";
        case NICE_CANDIDATE_TYPE_PEER_REFLEXIVE:
            return "prflx";
        case NICE_CANDIDATE_TYPE_RELAYED:
            return "relay";
        default:
            return "unknown";
    }
}

void NetworkManager::candidateGatheringDone(NiceAgent *agent, guint stream_id, gpointer user_data) {
    NetworkManager* nm = static_cast<NetworkManager*>(user_data);
    GSList *candidates = nice_agent_get_local_candidates(nm->agent, stream_id, 1);

    for (GSList *i = candidates; i; i = i->next) {
        NiceCandidate *cand = (NiceCandidate *)i->data;

        // Получаем IP-адрес из NiceAddress
        char ip[INET6_ADDRSTRLEN];
        memset(ip, 0, sizeof(ip));
        nice_address_to_string(&(cand->addr), ip);

        // Получаем порт из NiceAddress
        uint16_t port = nice_address_get_port(&(cand->addr));

        // Формируем строку с информацией о кандидате
        std::string candidateInfo = "Found candidate: "
            + std::string(cand->foundation) + " type: " + getCandidateTypeName(cand->type)
            + " base IP: " + std::string(ip)
            + " port: " + std::to_string(port);

        // Выводим информацию о кандидате
        // std::cout << candidateInfo << std::endl;


        nm->candidates.push_back(candidateInfo);
    }

    g_slist_free_full(candidates, (GDestroyNotify)nice_candidate_free);
    g_main_loop_quit(nm->main_loop);
}

// Метод для получения всех найденных кандидатов
const std::vector<std::string>& NetworkManager::getCandidates() const {
    return candidates;
}

std::vector<std::string> NetworkManager::getSrflxCandidates() const {
    std::vector<std::string> srflxCandidates;
    for (const auto& candidate : candidates) {
        if (candidate.find("type: srflx") != std::string::npos) {
            srflxCandidates.push_back(candidate);
        }
    }
    return srflxCandidates;
}


bool NetworkManager::is_tor_running(int control_port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Ошибка создания сокета.\n";
        return false;
    }

    // Настройка адреса для подключения
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(control_port);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Установка таймаута на подключение
    struct timeval timeout;
    timeout.tv_sec = 2;  // 2 секунды
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    // Попытка подключения
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sock);
        return false;  // Tor не запущен
    }

    // Отправка команды GETINFO version
    const char* command = "GETINFO version\r\n";
    send(sock, command, strlen(command), 0);

    // Получение ответа
    char buffer[1024];
    ssize_t bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
    close(sock);

    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';  // Завершаем строку
        std::string response(buffer);
        if (response.find("version=") != std::string::npos) {
            return true;  // Tor запущен
        }
    }

    return false;  // Tor не запущен или ответ некорректный
}