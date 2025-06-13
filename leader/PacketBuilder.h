#ifndef PACKETBUILDER_H
#define PACKETBUILDER_H

#pragma once
#include <vector>
#include <cstdint>
#include "MerkleTreeBuilder.h"

class PacketBuilder {
public:
    static std::vector<uint8_t> build(
        const std::vector<uint8_t>& header,        // 108 bytes
        const std::vector<uint8_t>& fullChunk,     // 24B header + payload
        const MerkleProof& proof                   // 5 × 20B sibling hashes
    );

    static std::vector<std::vector<uint8_t>> buildPackets(const std::vector<std::vector<uint8_t>>& headers, const std::vector<std::vector<uint8_t>>& chunksWithChunkHeaders, std::vector<std::vector<MerkleProof>> merkleProofs);

    static void setBroadcastBit(std::vector<uint8_t> packet, bool value);
};

#endif