#include "UdpReceiver.h"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

UDPReceiver::UDPReceiver(uint16_t port) {
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    std::cout << "✅ UDP Receiver listening on port " << port << "\n";
}

UDPReceiver::~UDPReceiver() {
    close(sockfd);
}

void UDPReceiver::receiveLoop() {
    uint8_t buffer[2048];

    while (true) {
        ssize_t bytesReceived = recvfrom(sockfd, buffer, sizeof(buffer), 0, nullptr, nullptr);
        if (bytesReceived < 0) {
            perror("recvfrom failed");
            continue;
        }

        std::cout << "📦 Received packet of size: " << bytesReceived << " bytes\n";

        const size_t HEADER_OVERHEAD = 232;
        if (bytesReceived <= HEADER_OVERHEAD) {
            std::cout << "⚠️ Packet too small, no payload\n";
            continue;
        }

        uint16_t chunkId = (static_cast<uint16_t>(buffer[230]) << 8) | buffer[231];
        std::cout << "🧩 Chunk ID: " << chunkId << "\n";

        size_t payloadSize = bytesReceived - HEADER_OVERHEAD;
        const uint8_t* payload = buffer + HEADER_OVERHEAD;

        // std::cout << "🧾 Payload (" << payloadSize << " bytes): ";
        // for (size_t i = 0; i < payloadSize; ++i) {
        //     char c = static_cast<char>(payload[i]);
        //     if (std::isprint(c))
        //         std::cout << c;
        //     else
        //         std::cout << '.';
        // }
        std::cout << "\n\n";
        std::cout<<"-----------";
    }
}

