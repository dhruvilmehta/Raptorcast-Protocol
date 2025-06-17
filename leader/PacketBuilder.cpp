#include "PacketBuilder.h"
#include <stdexcept>
#include <iostream>
#include <chrono>

std::vector<uint8_t> PacketBuilder::build(
    const std::vector<uint8_t>& header,
    const std::vector<uint8_t>& fullChunk,
    const MerkleProof& proof
) {
    if (header.size() != 108) {
        throw std::invalid_argument("Header must be 108 bytes");
    }
    if (fullChunk.size() < 24) {
        throw std::invalid_argument("Chunk too small to contain 24B header");
    }
    if (proof.siblingHashes.size() != 5) {
        throw std::invalid_argument("Merkle proof must contain 5 hashes (20B each)");
    }

    std::vector<uint8_t> packet;

    // appending 100-byte Merkle proof (5 × 20 byte sibling hashes)
    for (const auto& hash : proof.siblingHashes) {
        packet.insert(packet.end(), hash.begin(), hash.begin() + 20);
    }

    // appending 108-byte RaptorCast header
    packet.insert(packet.end(), header.begin(), header.end());

    // appending 24-byte chunk header
    packet.insert(packet.end(), fullChunk.begin(), fullChunk.begin() + 24);
    // std::cout<<"Chunk Merkle Leaf index"<<(int)packet[228]<<std::endl;

    // appending payload (main block data from text file)(chunk data after chunk header)
    packet.insert(packet.end(), fullChunk.begin() + 24, fullChunk.end());

    return packet;
}

std::vector<std::vector<uint8_t>> PacketBuilder::buildPackets(const std::vector<std::vector<uint8_t>>& headers, const std::vector<std::vector<uint8_t>>& chunksWithChunkHeaders, std::vector<std::vector<MerkleProof>> merkleProofs){
    auto start = std::chrono::high_resolution_clock::now();
    std::vector<std::vector<uint8_t>> packets;

    for (size_t group = 0; group * 32 < chunksWithChunkHeaders.size(); ++group) {
        for (size_t i = 0; i < 32; ++i) {
            size_t globalIndex = group * 32 + i;
            if (globalIndex >= chunksWithChunkHeaders.size()) break;

            std::vector<uint8_t> packet = build(
                headers[group],
                chunksWithChunkHeaders[globalIndex],
                merkleProofs[group][i]
            );
            // std::cout<<"Total Packet size: "<<packet.size()<<std::endl;
            // std::cout<<"Header size: "<<headers[group].size()<<" ";
            // std::cout<<"Merkle Proof size: "<<merkleProofs[group].size()<<" ";
            // std::cout<<"Chunks size (ChunkHeader(24)+Payload(1268)): "<<chunksWithChunkHeaders[i].size()<<std::endl;
            packets.push_back(packet);
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout<<"Total Number of Packets "<<packets.size()<<std::endl;
    std::cout << "Time taken to build Packets: " << duration.count() << " ms" << std::endl;
    return packets;
}