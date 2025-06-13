#ifndef VALIDATOR_H
#define VALIDATOR_H

#include <string>
#include <vector>
#include <chrono>
#include <map>

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
    // std::chrono::steady_clock::time_point block_start_time;
    // std::vector<std::vector<uint8_t>> stored_packets;
    std::map<std::vector<uint8_t>, std::vector<std::vector<uint8_t>>> stored_packets;
    std::vector<ValidatorInfo> other_validators; // Changed to ValidatorInfo
    void processPackets(const std::vector<uint8_t>& block_hash);
    void printPackets(const std::vector<uint8_t>& block_hash);
    
    public:
    Validator(std::string addr, uint16_t p, double s);
    ~Validator();
    void run();
    void receivePacket(const std::vector<uint8_t>& block_hash);
    void rebroadcastPacket(const std::vector<uint8_t>& packet);
};

#endif