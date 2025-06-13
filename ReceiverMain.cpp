#include "UdpReceiver.h"

int main() {
    UdpReceiver receiver(9000);
    receiver.receiveLoop();
    return 0;
}
