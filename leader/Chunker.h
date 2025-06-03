#pragma once
#include <vector>
#include <cstdint>

class Chunker {
public:
    static std::vector<std::vector<uint8_t>> splitIntoChunks(const std::vector<uint8_t>& blockData, size_t chunkSize = 1268);
};
