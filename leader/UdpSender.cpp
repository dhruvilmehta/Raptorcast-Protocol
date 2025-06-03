#include "UdpSender.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iostream>

UDPSender::UDPSender(const std::string& destinationIp, uint16_t port) {
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed");
        return;
    }

    memset(&destAddr, 0, sizeof(destAddr));
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = htons(port);
    inet_pton(AF_INET, destinationIp.c_str(), &destAddr.sin_addr);
}

UDPSender::~UDPSender() {
    close(sockfd);
}

bool UDPSender::sendPacket(const std::vector<uint8_t>& data) {
    ssize_t sent = sendto(sockfd, data.data(), data.size(), 0,
                          (struct sockaddr*)&destAddr, sizeof(destAddr));
    return sent == (ssize_t)data.size();
}

void UDPSender::sendPackets(const std::vector<std::vector<uint8_t>>& packets){
    for (const auto& packet : packets) {
        if (!sendPacket(packet)) {
            std::cerr << "Failed to send chunk\n";
        }else {
            std::cout<<"Packet Sent Size: "<<packet.size()<<std::endl;
        }
    }
}