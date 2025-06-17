#pragma once
#include <vector>
#include <string>
#include <cstdint>

struct MerkleProof {
    std::vector<std::vector<uint8_t>> siblingHashes;  // one per level
};

class MerkleTreeBuilder {
public:
    std::pair<std::vector<std::vector<uint8_t>>, std::vector<std::vector<MerkleProof>>>
    buildMerkleTreeWithProofs(const std::vector<std::vector<uint8_t>>& chunks);

    static std::pair<std::vector<uint8_t>, std::vector<MerkleProof>> build(const std::vector<std::vector<uint8_t>>& chunks);

    static std::vector<uint8_t> hash(const std::vector<uint8_t>& data);
};
