#include "MerkleTreeBuilder.h"
#include <openssl/sha.h>
#include <stdexcept>
#include <iostream>

// calc sha256 and with only first 20 bytes
std::vector<uint8_t> MerkleTreeBuilder::hash(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> digest(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), digest.data());
    return std::vector<uint8_t>(digest.begin(), digest.begin()+20);
}

std::pair<std::vector<std::vector<uint8_t>>, std::vector<std::vector<MerkleProof>>>
MerkleTreeBuilder::buildMerkleTreeWithProofs(const std::vector<std::vector<uint8_t>>& chunks) {
    std::vector<std::vector<uint8_t>> merkleRoots;
    std::vector<std::vector<MerkleProof>> allProofs;

    for (size_t group = 0; group * 32 < chunks.size(); ++group) {
        size_t groupStart = group * 32;
        size_t groupEnd = groupStart + 32;

        std::vector<std::vector<uint8_t>> chunkGroup(
            chunks.begin() + groupStart,
            chunks.begin() + groupEnd
        );

        auto [merkleRoot, proofs] = build(chunkGroup);

        merkleRoots.push_back(merkleRoot);
        allProofs.push_back(proofs);
    }

    return {merkleRoots, allProofs};
}

std::pair<std::vector<uint8_t>, std::vector<MerkleProof>> MerkleTreeBuilder::build(const std::vector<std::vector<uint8_t>>& chunks){
    if (chunks.empty()) throw std::invalid_argument("Chunks must not be empty");
    // for(int i=0;i<chunks.size();i++){
    //     std::cout<<chunks[i].size();
    // }
    // std::cout<<"-----------------------------------------------------------------"<<std::endl;
    size_t leafCount = chunks.size();
    size_t levelSize = leafCount;

    // building leaves (sha256(chunk)) // only first 20 bytes are considered. hash() only return first 20 bytes
    std::vector<std::vector<uint8_t>> currentLevel;
    for (const auto& chunk : chunks){
        // std::vector<uint8_t> merkleLeafHash=hash(chunk);
        // for(int i=0;i<merkleLeafHash.size();i++){
        //     std::cout<<(int)merkleLeafHash[i];
        // }
        // std::cout<<std::endl;
        currentLevel.push_back(hash(chunk));
    }

    
    std::vector<std::vector<std::vector<uint8_t>>> treeLevels;
    treeLevels.push_back(currentLevel);

    // building tree upward
    while (currentLevel.size() > 1) {
        std::vector<std::vector<uint8_t>> nextLevel;
        for (size_t i = 0; i < currentLevel.size(); i += 2) {
            std::vector<uint8_t> left = currentLevel[i];
            std::vector<uint8_t> right = (i + 1 < currentLevel.size()) ? currentLevel[i + 1] : left;

            std::vector<uint8_t> combined(left);
            combined.insert(combined.end(), right.begin(), right.end());

            nextLevel.push_back(hash(combined));
        }
        // std::cout<<"Level size"<<currentLevel.size()<<std::endl;
        currentLevel = nextLevel;
        treeLevels.push_back(currentLevel);
    }

    std::vector<uint8_t> merkleRoot = currentLevel.front();

    // generating merkle proofs for each leaf
    std::vector<MerkleProof> proofs(leafCount);
    for (size_t i = 0; i < leafCount; ++i) {
        size_t idx = i;
        for (size_t level = 0; level < treeLevels.size() -1; ++level) {
            const auto& siblings = treeLevels[level];
            size_t siblingIdx = (idx % 2 == 0) ? idx + 1 : idx - 1;
            proofs[i].siblingHashes.push_back(siblings[siblingIdx]);
            idx /= 2; // going to upper level.
        }
    }

    return {merkleRoot, proofs};
}
