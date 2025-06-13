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

    // according to the blog
    // recipient 20 Bytes
    header.insert(header.end(), recipient.begin(), recipient.end());

    // Add leaf index 1 Byte
    header.push_back(leafIndex);

    // Reserved 1 Byte
    header.push_back(0x00);

    // Chunk ID 2 Bytes (big endian)
    header.push_back((chunkId >> 8) & 0xFF);
    header.push_back(chunkId & 0xFF);

    //total becomes 24 bytes
    return header;
}

std::vector<std::vector<uint8_t>> ChunkHeaderBuilder::buildFromRawChunks(std::vector<std::vector<uint8_t>> rawChunks, std::vector<uint8_t> recipient){
    std::vector<std::vector<uint8_t>> chunksWithChunkHeaders;

    for (size_t group = 0; group * 32 < rawChunks.size(); ++group) {
        size_t groupStart = group * 32;
    
        for (size_t i = 0; i < 32; ++i) {
            uint16_t chunkId = static_cast<uint16_t>(groupStart + i);  // Global index
            uint8_t leafIndex = static_cast<uint8_t>(i);               // Index in group
    
            std::vector<uint8_t> payload;

            // Use real chunk if it exists, since it is possible to not exist as well because we are compulsorily forming group of 32 chunks
            if ((groupStart + i) < rawChunks.size()) {
                payload = rawChunks[groupStart + i];
            } else {
                // or use dummy chunk/padding
                // padding chunk 1268 Bytes of 0
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
