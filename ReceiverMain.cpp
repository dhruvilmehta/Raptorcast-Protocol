#include "UdpReceiver.h"

int main() {
    UDPReceiver receiver(9000);
    receiver.receiveLoop();
    return 0;
}
