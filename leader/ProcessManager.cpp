#include "ProcessManager.h"
#include "BlockLoader.h"
#include "Chunker.h"
#include "ChunkHeaderBuilder.h"
#include "MerkleTreeBuilder.h"
#include "HeaderBuilder.h"
#include <chrono>
#include "PacketBuilder.h"
#include "UdpSender.h"

void ProcessManager::processBlock(const std::string& filename){
    std::vector<uint8_t> blockData = BlockLoader::loadTextBlock("block.txt");
    std::vector<std::vector<uint8_t>> rawChunks = Chunker::splitIntoChunks(blockData);
    std::vector<std::vector<uint8_t>> chunksWithChunkHeaders=ChunkHeaderBuilder::buildFromRawChunks(rawChunks);

    std::pair<std::vector<std::vector<uint8_t>>, std::vector<std::vector<MerkleProof>>> result =
    MerkleTreeBuilder::buildMerkleTreeWithProofs(chunksWithChunkHeaders);

    std::vector<std::vector<uint8_t>> merkleRoots = result.first;
    std::vector<std::vector<MerkleProof>> proofs = result.second;

    // Dummy block hash (SHA256 of blockData, take first 20 bytes)
    std::vector<uint8_t> fullBlockHash = MerkleTreeBuilder::hash(blockData);
    std::vector<uint8_t> blockHash(fullBlockHash.begin(), fullBlockHash.begin() + 20);

    std::vector<std::vector<uint8_t>> groupHeaders=HeaderBuilder::buildGroupHeaders(merkleRoots, blockData.size(), blockHash);

    std::vector<std::vector<uint8_t>> packets=PacketBuilder::buildPackets(groupHeaders, chunksWithChunkHeaders, proofs);

    // UDPSender sender("127.0.0.1", 9000);
    // sender.sendPackets(packets);
    // sender.~UDPSender();
}