#ifndef UDP_RECEIVER_HPP
#define UDP_RECEIVER_HPP

#include <cstdint>

class UDPReceiver {
public:
    UDPReceiver(uint16_t port);
    ~UDPReceiver();

    void receiveLoop();  // starts listening

private:
    int sockfd;
};

#endif // UDP_RECEIVER_HPP
