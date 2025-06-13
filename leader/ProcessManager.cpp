#include "ProcessManager.h"
#include "BlockLoader.h"
#include "Chunker.h"
#include "ChunkHeaderBuilder.h"
#include "MerkleTreeBuilder.h"
#include "HeaderBuilder.h"
#include <chrono>
#include "PacketBuilder.h"
#include "UdpSender.h"
#include <random>
#include <map>
#include <algorithm>
#include <iostream>

// Structure for validator info
struct Validator {
    std::string address; // IP address
    uint16_t port;       // Port
    double stake;        // Stake proportion (sums to 1.0)
};

void ProcessManager::processBlock(const std::string& filename){
    std::vector<uint8_t> blockData = BlockLoader::loadTextBlock("block.txt");
    std::vector<std::vector<uint8_t>> rawChunks = Chunker::splitIntoChunks(blockData);
    std::vector<std::vector<uint8_t>> chunksWithChunkHeaders=ChunkHeaderBuilder::buildFromRawChunks(rawChunks);

    std::pair<std::vector<std::vector<uint8_t>>, std::vector<std::vector<MerkleProof>>> result =
    MerkleTreeBuilder::buildMerkleTreeWithProofs(chunksWithChunkHeaders);

    std::vector<std::vector<uint8_t>> merkleRoots = result.first;
    std::cout<<"Merkle Root Size"<<merkleRoots[0].size()<<std::endl;

    std::vector<std::vector<MerkleProof>> proofs = result.second;
    // std::cout<<"Proof Size"<<proofs[0][0].siblingHashes.size()<<std::endl;
    // Dummy block hash (SHA256 of blockData, take first 20 bytes)
    std::vector<uint8_t> fullBlockHash = MerkleTreeBuilder::hash(blockData);
    std::vector<uint8_t> blockHash(fullBlockHash.begin(), fullBlockHash.begin() + 20);

    std::vector<std::vector<uint8_t>> groupHeaders=HeaderBuilder::buildGroupHeaders(merkleRoots, blockData.size(), blockHash);

    std::vector<std::vector<uint8_t>> packets=PacketBuilder::buildPackets(groupHeaders, chunksWithChunkHeaders, proofs);
    std::cout<<"Total Packets to transmit "<<packets.size()<<std::endl;

    std::vector<Validator> validators = {
        {"127.0.0.1", 9001, 0.4}, // 40% stake
        {"127.0.0.1", 9002, 0.3}, // 30% stake
        {"127.0.0.1", 9003, 0.2}, // 20% stake
        {"127.0.0.1", 9004, 0.1}  // 10% stake
    };

    size_t assigned = 0;
    for (const auto& validator : validators) {
        size_t num_chunks = static_cast<size_t>(packets.size() * validator.stake + 0.5); // Round to nearest
        if (assigned + num_chunks > packets.size()) num_chunks = packets.size() - assigned;
        std::vector<std::vector<uint8_t>> validator_packets(packets.begin() + assigned, packets.begin() + assigned + num_chunks);
        assigned += num_chunks;

        // setting broadcast flag to 1 and send
        for (auto& packet : validator_packets) {
            PacketBuilder::setBroadcastBit(packet, true);
        }
        std::cout<<"Sending Packets to validator at"<<validator.port<<". Packet size: "<<validator_packets.size()<<std::endl;
        UDPSender sender(validator.address, validator.port); // sending to each validator
        sender.sendPackets(validator_packets);
    }
}