#pragma once
#include <vector>
#include <cstdint>

class HeaderBuilder {
public:
    static std::vector<uint8_t> build(
        const std::vector<uint8_t>& merkleRoot,       // 32 bytes
        const std::vector<uint8_t>& blockHashFirst20, // 20 bytes
        uint64_t epoch,
        uint64_t timestampMillis,
        uint16_t version,
        bool isBroadcast,
        uint32_t blockLength,
        const std::vector<uint8_t>& privateKey         // to sign header+merkleRoot
    );

    static std::vector<std::vector<uint8_t>> buildGroupHeaders(std::vector<std::vector<uint8_t>> merkleRoots, std::size_t blockSize, std::vector<uint8_t>);
};
