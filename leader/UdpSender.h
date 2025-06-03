#pragma once
#include <vector>
#include <cstdint>
#include <string>
#include <netinet/in.h>

class UDPSender {
public:
    UDPSender(const std::string& destinationIp, uint16_t port);
    ~UDPSender();
    bool sendPacket(const std::vector<uint8_t>& data);
    void sendPackets(const std::vector<std::vector<uint8_t>>& packets);

private:
    int sockfd;
    struct sockaddr_in destAddr;
};
