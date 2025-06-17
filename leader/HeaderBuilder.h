#pragma once
#include <vector>
#include <cstdint>
#include "Signer.h"

class HeaderBuilder {
public:
    HeaderBuilder();
    
    std::vector<uint8_t> build(
        const std::vector<uint8_t>& merkleRoot,
        const std::vector<uint8_t>& blockHashFirst20,
        uint64_t epoch,
        uint64_t timestampMillis,
        uint16_t version,
        bool isBroadcast,
        uint32_t blockLength
    );

    std::vector<std::vector<uint8_t>> buildGroupHeaders(std::vector<std::vector<uint8_t>> merkleRoots, std::size_t blockSize, std::vector<uint8_t>);

    private:
    Signer signer; 
};
