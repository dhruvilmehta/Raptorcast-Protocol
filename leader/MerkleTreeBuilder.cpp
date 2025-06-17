#include "MerkleTreeBuilder.h"
#include <openssl/sha.h>
#include <stdexcept>
#include <iostream>
#include <future>
#include <chrono>

// calc sha256 and with only first 20 bytes
std::vector<uint8_t> MerkleTreeBuilder::hash(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> digest(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), digest.data());
    return std::vector<uint8_t>(digest.begin(), digest.begin()+20);
}

// std::pair<std::vector<std::vector<uint8_t>>, std::vector<std::vector<MerkleProof>>>
// MerkleTreeBuilder::buildMerkleTreeWithProofs(const std::vector<std::vector<uint8_t>>& chunks) {
//     auto start = std::chrono::high_resolution_clock::now();
//     std::vector<std::vector<uint8_t>> merkleRoots;
//     std::vector<std::vector<MerkleProof>> allProofs;

//     for (size_t group = 0; group * 32 < chunks.size(); ++group) {
//         size_t groupStart = group * 32;
//         size_t groupEnd = groupStart + 32;

//         std::vector<std::vector<uint8_t>> chunkGroup(
//             chunks.begin() + groupStart,
//             chunks.begin() + groupEnd
//         );

//         auto [merkleRoot, proofs] = build(chunkGroup);

//         merkleRoots.push_back(merkleRoot);
//         allProofs.push_back(proofs);
//     }

//     // size_t groupCount = (chunks.size() + 31) / 32;
//     // std::vector<std::future<std::pair<std::vector<uint8_t>, std::vector<MerkleProof>>>> futures;
//     // for (size_t group = 0; group < groupCount; ++group) {
//     //     size_t groupStart = group * 32;
//     //     size_t groupEnd = std::min(groupStart + 32, chunks.size());

//     //     std::vector<std::vector<uint8_t>> chunkGroup(chunks.begin() + groupStart, chunks.begin() + groupEnd);

//     //     futures.push_back(std::async(std::launch::async, [this, chunkGroup]() -> std::pair<std::vector<uint8_t>, std::vector<MerkleProof>> {
//     //         return this->build(chunkGroup);
//     //     }));

//     // }

//     // // Collect results
//     // for (auto& future : futures) {
//     //     auto [merkleRoot, proofs] = future.get();
//     //     merkleRoots.push_back(merkleRoot);
//     //     allProofs.push_back(proofs);
//     // }


//     auto end = std::chrono::high_resolution_clock::now(); // End timing
//     auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
//     std::cout << "Time taken by buildMerkleTreeWithProofs: " << duration.count() << " ms" << std::endl;

//     return {merkleRoots, allProofs};
// }

#include <thread>
#include <mutex>

std::pair<std::vector<std::vector<uint8_t>>, std::vector<std::vector<MerkleProof>>>
MerkleTreeBuilder::buildMerkleTreeWithProofs(const std::vector<std::vector<uint8_t>>& chunks) {
    auto start = std::chrono::high_resolution_clock::now();
    std::vector<std::vector<uint8_t>> merkleRoots;
    std::vector<std::vector<MerkleProof>> allProofs;

    size_t groupCount = (chunks.size() + 31) / 32;
    // unsigned int maxThreads = std::thread::hardware_concurrency();
    // std::cout<<maxThreads<<std::endl;
    // if (maxThreads == 0) maxThreads = 4; // fallback to 4 if unknown
    unsigned int maxThreads=5;
    // Pre-size the output vectors
    merkleRoots.resize(groupCount);
    allProofs.resize(groupCount);

    std::mutex outputMutex; // Protect output writes (optional if each thread has exclusive range)

    auto worker = [&](size_t startGroup, size_t endGroup) {
        for (size_t group = startGroup; group < endGroup; ++group) {
            size_t groupStart = group * 32;
            size_t groupEnd = std::min(groupStart + 32, chunks.size());

            std::vector<std::vector<uint8_t>> chunkGroup(chunks.begin() + groupStart, chunks.begin() + groupEnd);

            auto [merkleRoot, proofs] = this->build(chunkGroup);

            // Direct write (safe because unique indices per thread)
            merkleRoots[group] = merkleRoot;
            allProofs[group] = proofs;
        }
    };

    std::vector<std::thread> threads;
    size_t groupsPerThread = (groupCount + maxThreads - 1) / maxThreads;

    for (unsigned int t = 0; t < maxThreads; ++t) {
        size_t startGroup = t * groupsPerThread;
        size_t endGroup = std::min(startGroup + groupsPerThread, groupCount);
        if (startGroup >= endGroup) break; // no more work

        // auto startSpawn = std::chrono::high_resolution_clock::now(); // Start spawn timing
        threads.emplace_back(worker, startGroup, endGroup);
        // auto endSpawn = std::chrono::high_resolution_clock::now(); // End spawn timing
        // auto spawnDuration = std::chrono::duration_cast<std::chrono::microseconds>(endSpawn - startSpawn);
        // std::cout << "Time to spawn thread " << t << ": " << spawnDuration.count() << " µs" << std::endl;
    }

    for (auto& th : threads) {
        th.join();  
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "Time taken to build MerkleTreeWithProofs: " << duration.count() << " ms" << std::endl;

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
