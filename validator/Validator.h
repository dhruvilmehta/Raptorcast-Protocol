#ifndef VALIDATOR_H
#define VALIDATOR_H

#include <string>
#include <vector>
#include <chrono>
#include <map>
#include <queue>
#include <condition_variable>
#include <mutex>
#include <thread>
#include "SignatureVerifier.h"

struct ValidatorInfo {
    std::string address;
    uint16_t port;
    double stake;
};

class Validator {
private:
    std::string address;
    uint16_t port;
    double stake;
    std::map<std::vector<uint8_t>, std::vector<std::vector<uint8_t>>> stored_packets;
    std::vector<ValidatorInfo> other_validators; // Changed to ValidatorInfo
    void processPackets(const std::vector<uint8_t>& block_hash);
    void printPackets(const std::vector<uint8_t>& block_hash);
    std::queue<std::vector<uint8_t>> packetQueue; // Queue for received packets
    std::mutex queueMutex; // Mutex for queue access
    std::condition_variable cv; // Condition variable for signaling
    bool running = true; // Control loop
    std::thread workerThread; // Single worker thread
    int count = 0;
    std::mutex coutMutex;
    int rebroadcastCount=0;
    SignatureVerifier verifier;

    
    public:
    Validator(std::string addr, uint16_t p, double s);
    ~Validator();
    void run();
    void receivePacket(const std::vector<uint8_t>& block_hash);
    void rebroadcastPacket(const std::vector<uint8_t>& packet);
};

#endif