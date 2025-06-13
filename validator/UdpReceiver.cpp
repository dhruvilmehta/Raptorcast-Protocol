#include "UdpReceiver.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <stdexcept>

UdpReceiver::UdpReceiver(std::string addr, uint16_t p) : address(addr), port(p) {
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) throw std::runtime_error("Socket creation failed");

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, address.c_str(), &server_addr.sin_addr);

    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sockfd);
        throw std::runtime_error("Bind failed");
    }
}

UdpReceiver::~UdpReceiver() {
    close(sockfd);
}

std::vector<uint8_t> UdpReceiver::receivePacket() {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    uint8_t buffer[1500]; // Adjust size based on max packet size
    int n = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&client_addr, &addr_len);
    if (n < 0) return std::vector<uint8_t>(); // Error handling

    std::vector<uint8_t> packet(buffer, buffer + n);
    return packet;

    // struct sockaddr_in client_addr;
    // socklen_t addr_len = sizeof(client_addr);
    // uint8_t buffer[1024];
    // fd_set readfds;
    // struct timeval tv;
    // FD_ZERO(&readfds);
    // FD_SET(sockfd, &readfds);
    // tv.tv_sec = 1; // 1-second timeout
    // tv.tv_usec = 0;

    // int rv = select(sockfd + 1, &readfds, NULL, NULL, &tv);
    // if (rv == -1) return std::vector<uint8_t>(); // Error
    // if (rv == 0) return std::vector<uint8_t>();   // Timeout

    // int n = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&client_addr, &addr_len);
    // if (n < 0) return std::vector<uint8_t>(); // Error

    // return std::vector<uint8_t>(buffer, buffer + n);
}