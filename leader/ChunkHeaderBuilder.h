#pragma once
#include <vector>
#include <cstdint>

class ChunkHeaderBuilder {
public:
    static std::vector<uint8_t> build(
        uint16_t chunkId,
        uint8_t leafIndex,
        const std::vector<uint8_t>& recipient
    );

    static std::vector<std::vector<uint8_t>> buildFromRawChunks(std::vector<std::vector<uint8_t>>, std::vector<uint8_t> recipient= std::vector<uint8_t>(20, 0xCD));
};
