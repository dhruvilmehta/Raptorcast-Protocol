#ifndef UDPRECEIVER_H
#define UDPRECEIVER_H

#include <vector>
#include <string>
#include <cstdint>

class UdpReceiver {
private:
    std::string address;
    uint16_t port;
    int sockfd;

public:
    UdpReceiver(std::string addr, uint16_t p);
    ~UdpReceiver();
    std::vector<uint8_t> receivePacket();
};

#endif