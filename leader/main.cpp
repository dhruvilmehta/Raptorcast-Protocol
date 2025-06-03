#include "BlockLoader.h"
#include "Chunker.h"
#include "MerkleTreeBuilder.h"
#include "PacketBuilder.h"
#include <iostream>
#include <iomanip>
#include <chrono>
#include "ChunkHeaderBuilder.h"
#include "HeaderBuilder.h"
#include "UdpSender.h"
#include "ProcessManager.h"

int main() {
    ProcessManager::processBlock("block.txt");
    // // Load block
    // std::vector<uint8_t> blockData = BlockLoader::loadTextBlock("block.txt");
    // std::cout << "Loaded block of size: " << blockData.size() << " bytes\n";

    // // Chunk block
    // std::vector<std::vector<uint8_t>> chunks = Chunker::splitIntoChunks(blockData);
    // std::cout << "Split into " << chunks.size() << " chunks\n";

    // std::vector<std::vector<uint8_t>> fullChunkGroup;

    // // Dummy recipient (20 bytes)
    // std::vector<uint8_t> recipient(20, 0xCD);

    // uint16_t groupStartChunkId = 0;  // starting from first group

    // for (size_t group = 0; group * 32 < chunks.size(); ++group) {
    //     size_t groupStart = group * 32;
    
    //     for (size_t i = 0; i < 32; ++i) {
    //         uint16_t chunkId = static_cast<uint16_t>(groupStart + i);  // Global index
    //         uint8_t leafIndex = static_cast<uint8_t>(i);               // Index in group
    
    //         std::vector<uint8_t> payload;

    //         // Use real chunk if it exists
    //         if ((groupStart + i) < chunks.size()) {
    //             payload = chunks[groupStart + i];
    //         } else {
    //             // Padding chunk (1268 bytes of zero)
    //             payload = std::vector<uint8_t>(1268, 0);
    //         }

    //         std::vector<uint8_t>  header = ChunkHeaderBuilder::build(chunkId, leafIndex, recipient);

    //         std::vector<uint8_t> fullChunk(header);
    //         fullChunk.insert(fullChunk.end(), payload.begin(), payload.end());
    //         // std::cout<<fullChunk.size()<<std::endl;
    //         fullChunkGroup.push_back(fullChunk);
    //     }
    // }    

    // // Chunks with chunk headers
    // chunks=fullChunkGroup;

    // // Pick first 32 chunks to build a Merkle group
    // std::vector<std::vector<uint8_t>> merkleRoots;
    // std::vector<std::vector<MerkleProof>> allProofs;

    // for (size_t group = 0; group * 32 < chunks.size(); ++group) {
    //     size_t groupStart = group * 32;
    //     size_t groupEnd = groupStart + 32;

    //     std::vector<std::vector<uint8_t>> chunkGroup(
    //         chunks.begin() + groupStart,
    //         chunks.begin() + groupEnd
    //     );

    //     auto [merkleRoot, proofs] = MerkleTreeBuilder::buildMerkleTreeWithProofs(chunkGroup);

    //     merkleRoots.push_back(merkleRoot);
    //     allProofs.push_back(proofs);
    // }

    // // Dummy block hash (SHA256 of blockData, take first 20 bytes)
    // std::vector<uint8_t> fullBlockHash = MerkleTreeBuilder::hash(blockData);
    // std::vector<uint8_t> blockHash(fullBlockHash.begin(), fullBlockHash.begin() + 20);

    // std::vector<std::vector<uint8_t>> groupHeaders;

    // uint64_t epoch = 1;
    // uint16_t version = 1;
    // bool isBroadcast = true;
    // uint32_t blockLength = static_cast<uint32_t>(blockData.size());
    
    // uint64_t timestampMillis = std::chrono::duration_cast<std::chrono::milliseconds>(
    //     std::chrono::system_clock::now().time_since_epoch()
    // ).count();
    
    // for (const auto& merkleRoot : merkleRoots) {
    //     std::vector<uint8_t> header = HeaderBuilder::build(
    //         merkleRoot,
    //         blockHash,
    //         epoch,
    //         timestampMillis,
    //         version,
    //         isBroadcast,
    //         blockLength,
    //         LEADER_PRIVATE_KEY
    //     );
    
    //     groupHeaders.push_back(header);
    // }
    
    // std::cout<<chunks.size()<<std::endl;
    // std::cout<<groupHeaders.size()<<std::endl;
    // std::cout<<"Header size: "<<groupHeaders[0].size()<<std::endl;
    // std::cout<<allProofs.size()<<std::endl;

    // std::vector<std::vector<uint8_t>> packets;

    // for (size_t group = 0; group * 32 < chunks.size(); ++group) {
    //     for (size_t i = 0; i < 32; ++i) {
    //         size_t globalIndex = group * 32 + i;
    //         if (globalIndex >= chunks.size()) break;

    //         std::vector<uint8_t> packet = PacketBuilder::build(
    //             groupHeaders[group],
    //             chunks[globalIndex],
    //             allProofs[group][i]
    //         );
    //         // std::cout<<"Total Packet size: "<<packet.size()<<std::endl;
    //         // std::cout<<"Header size: "<<groupHeaders[group].size();
    //         // std::cout<<"Merkle Proof size: "<<allProofs[group].size();
    //         // std::cout<<"Chunks size: "<<chunks[i].size();
    //         packets.push_back(packet);
    //         // std::cout << "Built packet of size: " << packet.size() << " bytes\n";
    //     }
    // }


    // Create sender (to localhost, port 9000)
    // UDPSender sender("127.0.0.1", 9000);
    // // sender.sendPacket(packets[0]);
    // // sender.sendPacket(packets[1]);
    // // Send all chunks
    // for (const auto& packet : packets) {
    //     if (!sender.sendPacket(packet)) {
    //         std::cerr << "Failed to send chunk\n";
    //     }else {
    //         std::cout<<"Packet Sent Size: "<<packet.size()<<std::endl;
    //     }
    // }

    return 0;
}
