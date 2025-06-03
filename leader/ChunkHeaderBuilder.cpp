#include "ChunkHeaderBuilder.h"
#include <stdexcept>

std::vector<uint8_t> ChunkHeaderBuilder::build(
    uint16_t chunkId,
    uint8_t leafIndex,
    const std::vector<uint8_t>& recipient
) {
    if (recipient.size() != 20)
        throw std::invalid_argument("Recipient must be exactly 20 bytes");

    std::vector<uint8_t> header;

    // 1. Add recipient (20 bytes)
    header.insert(header.end(), recipient.begin(), recipient.end());

    // 2. Add leaf index (1 byte)
    header.push_back(leafIndex);

    // 3. Reserved (1 byte)
    header.push_back(0x00);

    // 4. Chunk ID (2 bytes, big-endian)
    header.push_back((chunkId >> 8) & 0xFF);
    header.push_back(chunkId & 0xFF);

    return header;  // Total: 24 bytes
}

std::vector<std::vector<uint8_t>> ChunkHeaderBuilder::buildFromRawChunks(std::vector<std::vector<uint8_t>> rawChunks, std::vector<uint8_t> recipient){
    std::vector<std::vector<uint8_t>> chunksWithChunkHeaders;

    for (size_t group = 0; group * 32 < rawChunks.size(); ++group) {
        size_t groupStart = group * 32;
    
        for (size_t i = 0; i < 32; ++i) {
            uint16_t chunkId = static_cast<uint16_t>(groupStart + i);  // Global index
            uint8_t leafIndex = static_cast<uint8_t>(i);               // Index in group
    
            std::vector<uint8_t> payload;

            // Use real chunk if it exists
            if ((groupStart + i) < rawChunks.size()) {
                payload = rawChunks[groupStart + i];
            } else {
                // Padding chunk (1268 bytes of zero)
                payload = std::vector<uint8_t>(1268, 0);
            }

            std::vector<uint8_t>  header = build(chunkId, leafIndex, recipient);

            std::vector<uint8_t> fullChunk(header);
            fullChunk.insert(fullChunk.end(), payload.begin(), payload.end());
            chunksWithChunkHeaders.push_back(fullChunk);
        }
    }

    return chunksWithChunkHeaders;
}
