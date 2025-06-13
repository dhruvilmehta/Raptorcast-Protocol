#include "PacketBuilder.h"
#include <stdexcept>
#include <iostream>

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

    // 3. Append 100-byte Merkle proof (5 × 20-byte sibling hashes)
    for (const auto& hash : proof.siblingHashes) {
        for(int i=0;i<20;i++){
            std::cout<<(int)hash[i];
        }
        std::cout<<"-------"<<std::endl;
        // std::cout<<"Sibling Hash Size"<<hash.size()<<std::endl;
        // if (hash.size() != 20) {
        //     throw std::invalid_argument("Invalid hash size in Merkle proof");
        // }
        // Truncate to 20 bytes if hash is 32B
        packet.insert(packet.end(), hash.begin(), hash.begin() + 20);
    }

    // 1. Append 108-byte RaptorCast header
    packet.insert(packet.end(), header.begin(), header.end());

    // 2. Append 24-byte chunk header
    packet.insert(packet.end(), fullChunk.begin(), fullChunk.begin() + 24);
    std::cout<<"Chunk Merkle Leaf index"<<(int)packet[228]<<std::endl;
    // 4. Append payload (chunk data after chunk header)
    packet.insert(packet.end(), fullChunk.begin() + 24, fullChunk.end());

    return packet;
}

std::vector<std::vector<uint8_t>> PacketBuilder::buildPackets(const std::vector<std::vector<uint8_t>>& headers, const std::vector<std::vector<uint8_t>>& chunksWithChunkHeaders, std::vector<std::vector<MerkleProof>> merkleProofs){
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

    return packets;
}

void PacketBuilder::setBroadcastBit(std::vector<uint8_t> packet, bool value){
    if (packet.size() < 68) return; // Ensure header size is at least 68 bytes
    uint8_t& byte68 = packet[67];   // 0-based index, so 67 is the 68th byte
    if (value) {
        byte68 |= 0x80;             // Set MSB (bit 7) to 1
    } else {
        byte68 &= 0x7F;             // Set MSB (bit 7) to 0
    }
}
