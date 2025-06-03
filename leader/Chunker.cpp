#include "Chunker.h"

std::vector<std::vector<uint8_t>> Chunker::splitIntoChunks(const std::vector<uint8_t>& blockData, size_t chunkSize) {
    std::vector<std::vector<uint8_t>> chunks;

    size_t totalSize = blockData.size();
    size_t offset = 0;

    while (offset < totalSize) {
        size_t currentSize = std::min(chunkSize, totalSize - offset);
        chunks.emplace_back(blockData.begin() + offset, blockData.begin() + offset + currentSize);
        offset += currentSize;
    }

    return chunks;
}
