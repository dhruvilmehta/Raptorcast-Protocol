#include "Validator.h"
#include <iostream>
#include <thread>
#include <algorithm>
#include <fstream>
#include <vector>
#include <stdexcept>
#include <string>
#include "../leader/UdpSender.h"
#include "UdpReceiver.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <thread>
#include <future>
#include "SignatureVerifier.h"

// computing SHA256 and then concatenating to only 20B since we are only using 20Bytes
std::vector<uint8_t> computeHash(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> digest(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), digest.data());
    return std::vector<uint8_t>(digest.begin(), digest.begin()+20);
}

Validator::Validator(std::string addr, uint16_t p, double s) : address(addr), port(p), stake(s), verifier("../ec-secp256k1-pub-key.pem") {
    this->other_validators = {
        {"127.0.0.1", 9001, 0.4},
        {"127.0.0.1", 9002, 0.3},
        {"127.0.0.1", 9003, 0.2},
        {"127.0.0.1", 9004, 0.1}
    };
    std::cout << "Validator constructed at " << address << ":" << port << "\n";
     // Initialize single worker thread
    workerThread = std::thread([this]() {
        while (running) {
            std::vector<uint8_t> packet;
            {
                std::unique_lock<std::mutex> lock(queueMutex);
                // Wait with a timeout to keep thread awake
                if (cv.wait_for(lock, std::chrono::milliseconds(100), [this]() { return !running || !packetQueue.empty(); })) {
                    if (!running && packetQueue.empty()) break;
                    if (!packetQueue.empty()) {
                        packet = std::move(packetQueue.front());
                        packetQueue.pop();
                    }
                }
            }
            if (!packet.empty()) {
                {
                    std::lock_guard<std::mutex> lock(coutMutex); // Thread-safe cout
                    count++;
                    // std::cout << "" << count<<std::endl;
                    std::cout.flush(); // Ensure output is displayed
                }
                receivePacket(packet);
            }
        }
    });
}

Validator::~Validator() {
    std::cout << "Validator at " << address << ":" << port << " destroyed\n";
    running = false;
    cv.notify_one(); // Notify the single worker
    if (workerThread.joinable()) workerThread.join();
}

void Validator::run() {
    std::cout<<"Listening to packets"<<std::endl;
    UdpReceiver receiver(address, port);
    std::vector<std::future<void>> futures;
    while (true) {
        std::vector<uint8_t> packet = receiver.receivePacket();
        if (!packet.empty()) {
            // receivePacket(packet);


            // std::lock_guard<std::mutex> lock(queueMutex);
            packetQueue.push(packet);
            // cv.notify_one(); // Wake up the worker thread
        }
    }
}

void Validator::receivePacket(const std::vector<uint8_t>& packet) {
    if (packet.size() < 68) return;

    // Here when we receive the packet, the hash of the Main block data is stored packet[184-204] hence we can use the hash of the block as key in out hashmap. This is a temporary hashmap, once we receive desired number of packets and process the packets, we clear the map with that key.
    stored_packets[std::vector<uint8_t>(packet.begin() + 184, packet.begin() + 204)].push_back(packet);

    // We are setting the broadcast bit to 1 when we receive from leader, suggesting to broadcast the packets once received. To prevent infinite rebroadcasting, we set the broadcast bit to 0 so that the validator receiving it does not rebroadcast the packet again. 
    // Not sure how infinite rebroadcasting is prevented in actual Raptorcast.
    // std::cout<<(bool)(packet[167] & 0x80)<<std::endl;
    if (packet[167] & 0x80) {
        rebroadcastCount++;
        // std::cout<<rebroadcastCount;
        // std::cout<<"Broadcast"<<std::endl;
        rebroadcastPacket(packet);
    }else{
        // std::cout<<"2nd Layer (Hence no broadcasting)"<<std::endl;
    }

    // currently I am not using encoding scheme hence, I am harcoding the actual number of packets, for my test case its 32 packets, but after implementing encoding scheme, I can have some fixed number of packets to decode. (currently all the packets are original, not encoded with R10 or LT)
    // std::cout<<stored_packets[std::vector<uint8_t>(packet.begin() + 184, packet.begin() + 204)].size()<<std::endl;
    if (stored_packets[std::vector<uint8_t>(packet.begin() + 184, packet.begin() + 204)].size() >= 1200) {
        processPackets(std::vector<uint8_t>(packet.begin() + 184, packet.begin() + 204));
    }
}

void Validator::rebroadcastPacket(const std::vector<uint8_t>& packet) {
    std::vector<uint8_t> rebroadcast_packet = packet;
    rebroadcast_packet[167] &= 0x7F; // Set Broadcast flag to 0
    for (const auto& validator : other_validators) {
        if (validator.address != address || validator.port != port) {
            UDPSender sender(validator.address, validator.port);
            sender.sendPacket(rebroadcast_packet);
        }
    }
}

// for testing and printing purposes
// compare the packets based on Chunk ID and then based on Leaf index.
struct PacketComparator {
    bool operator()(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) const {
        uint16_t chunkIdA = (static_cast<uint16_t>(a[230]) << 8) | a[231]; // Chunk ID at 230-231
        uint16_t chunkIdB = (static_cast<uint16_t>(b[230]) << 8) | b[231];
        if (chunkIdA != chunkIdB) return chunkIdA < chunkIdB;
        return a[228] < b[228]; // Chunk Merkle leaf index at 228
    }
};

// bool verifySignature(const std::vector<uint8_t>& toHash,
//                      const std::vector<uint8_t>& signature,
//                      const std::string& publicKeyFile) {
//     if (signature.size() < 64) {
//         throw std::runtime_error("Invalid signature size");
//     }

//     // computing sha256 hash
//     std::vector<uint8_t> hashDigest(SHA256_DIGEST_LENGTH);
//     SHA256(toHash.data(), toHash.size(), hashDigest.data());

//     // via GPT
//     // Load public key from PEM file
//     FILE* fp = fopen(publicKeyFile.c_str(), "r");
//     if (!fp) throw std::runtime_error("Failed to open public key file");
//     EC_KEY* ecKey = PEM_read_EC_PUBKEY(fp, NULL, NULL, NULL);
//     fclose(fp);
//     if (!ecKey) throw std::runtime_error("Failed to read public key");

//     // Extract r and s from signature vector
//     BIGNUM* r = BN_bin2bn(&signature[0], 32, NULL);
//     BIGNUM* s = BN_bin2bn(&signature[32], 32, NULL);
//     if (!r || !s) {
//         EC_KEY_free(ecKey);
//         BN_free(r);
//         BN_free(s);
//         throw std::runtime_error("Failed to create BIGNUMs for r and s");
//     }

//     // Recreate ECDSA_SIG structure
//     ECDSA_SIG* sig = ECDSA_SIG_new();
//     if (!sig) {
//         EC_KEY_free(ecKey);
//         BN_free(r);
//         BN_free(s);
//         throw std::runtime_error("Failed to allocate ECDSA_SIG");
//     }

//     if (ECDSA_SIG_set0(sig, r, s) != 1) {
//         EC_KEY_free(ecKey);
//         ECDSA_SIG_free(sig);
//         BN_free(r);
//         BN_free(s); // Only if set0 fails, else ownership transferred
//         throw std::runtime_error("Failed to set r and s in signature");
//     }

//     // Verify the signature
//     int verifyStatus = ECDSA_do_verify(hashDigest.data(), SHA256_DIGEST_LENGTH, sig, ecKey);

//     // Cleanup
//     ECDSA_SIG_free(sig);
//     EC_KEY_free(ecKey);

//     return verifyStatus == 1; // 1 = valid, 0 = invalid, -1 = error
// }

// void Validator::processPackets(const std::vector<uint8_t>& block_hash) {
//     auto start = std::chrono::high_resolution_clock::now();
//     // printPackets(block_hash); // to save the data into txt file (for testing purposes)

//     std::cout << "Validator at " << address << ":" << port << " processing " << stored_packets[block_hash].size() << " packets for block hash: ";

//     bool allValid = true;
//     for (auto& packet : stored_packets[block_hash]) {
//         packet[167] |= 0x80;

//         // Extract signature (100-164) 65 Bytes and header data (165-207) 43 Bytes
//         std::vector<uint8_t> signature(packet.begin() + 100, packet.begin() + 165);
//         std::vector<uint8_t> headerData(packet.begin() + 165, packet.begin() + 208);

//         // chunk with chunk header from 208 till end;
//         std::vector<uint8_t> chunkData(packet.begin() + 208, packet.end());
//         // std::cout<<"ChunkData size"<<chunkData.size()<<std::endl;
//         std::vector<uint8_t> merkleLeafHash = computeHash(chunkData);

//         std::vector<std::vector<uint8_t>> siblingHashes;
//         // sibling hashes 20 Bytes each, total 5 hashes
//         for (size_t i = 0; i < 100; i += 20) {
//             siblingHashes.push_back(std::vector<uint8_t>(packet.begin() + i, packet.begin() + i + 20));
//         }

//         uint8_t leafIndex = packet[228]; // Chunk Merkle leaf index at 228
//         // std::cout<<"Chunk Merkle Leaf index"<<(int)packet[228]<<std::endl;

//         // Reconstructing Merkle root for this particular chunk;
//         std::vector<uint8_t> currentHash = merkleLeafHash;
//         size_t idx = leafIndex;
//         for (size_t i = 0; i < siblingHashes.size(); ++i) {
//             std::vector<uint8_t> concat;
//             if(idx%2==0){
//                 concat.insert(concat.end(), currentHash.begin(), currentHash.end());
//                 concat.insert(concat.end(), siblingHashes[i].begin(), siblingHashes[i].end());
//             }else{
//                 concat.insert(concat.end(), siblingHashes[i].begin(), siblingHashes[i].end());
//                 concat.insert(concat.end(), currentHash.begin(), currentHash.end());
//             }
//             idx/=2;
//             currentHash=computeHash(concat);
//         }
//         std::vector<uint8_t> merkleRoot = currentHash;
//         // std::cout<<"Merkle Root: ";
//         // for(int i=0;i<merkleRoot.size();i++){
//         //     std::cout<<(int)merkleRoot[i];
//         // }
//         // std::cout<<std::endl;

//         // Concatenating header data with Merkle root for signature verification
//         std::vector<uint8_t> dataToVerify = headerData;
//         dataToVerify.insert(dataToVerify.end(), merkleRoot.begin(), merkleRoot.end());

//         bool signatureValid=false;
        
//         signatureValid = verifier.verifySignature(dataToVerify, signature);
//         // std::cout<<"Signature verification"<<std::endl;

//         if (!signatureValid) {
//             std::cout << "Signature verification failed for packet with leaf index " << (int)leafIndex << "\n";
//             allValid = false;
//         } else {
//             // std::cout << "Signature and Merkle proof verified for leaf index " << (int)leafIndex << "\n";
//             uint16_t chunkId = (static_cast<uint16_t>(packet[230]) << 8) | packet[231]; // Chunk ID at 230-231
//             // std::cout << chunkId << " -- " << (int)leafIndex << std::endl;

//             // Extract and save payload (232 to end) (Just for testing)
//             // std::string payload(packet.begin() + 232, packet.end());
//             // std::string filename = "chunk_" + std::to_string(chunkId) + "_leaf_" + std::to_string(leafIndex) + ".txt";
//             // std::ofstream outFile(filename);
//             // if (outFile.is_open()) {
//             //     outFile << payload;
//             //     outFile.close();
//             //     std::cout << "Payload saved to " << filename << std::endl;
//             // } else {
//             //     std::cout << "Failed to open file " << filename << std::endl;
//             // }
//         }
//     }

//     if (allValid) {
//         std::cout << "All packets validated successfully\n";
//     } else {
//         std::cout << "Some packets failed validation, discarding block\n";
//     }

//     stored_packets.erase(block_hash);// clear the packets after processing (ideally, only after successfull processing)

//     auto end = std::chrono::high_resolution_clock::now();
//     auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
//     std::cout << "Time taken to process Packets: " << duration.count() << " ms" << std::endl;
// }

void Validator::processPackets(const std::vector<uint8_t>& block_hash) {
    auto start = std::chrono::high_resolution_clock::now();
    // printPackets(block_hash); // to save the data into txt file (for testing purposes)

    std::cout << "Validator at " << address << ":" << port << " processing " << stored_packets[block_hash].size() << " packets for block hash: ";

    bool allValid = true;
    size_t packetCount = stored_packets[block_hash].size();
    unsigned int maxThreads = std::min(25u, static_cast<unsigned int>(std::thread::hardware_concurrency()));
    std::vector<std::thread> threads;
    size_t packetsPerThread = (packetCount + maxThreads - 1) / maxThreads;

    std::mutex allValidMutex;

    auto worker = [&](size_t startIdx, size_t endIdx) {
        bool localValid = true;
        for (size_t i = startIdx; i < endIdx && i < packetCount; ++i) {
            auto& packet = stored_packets[block_hash][i];
            packet[167] |= 0x80;

            // Extract signature (100-164) 65 Bytes and header data (165-207) 43 Bytes
            std::vector<uint8_t> signature(packet.begin() + 100, packet.begin() + 165);
            std::vector<uint8_t> headerData(packet.begin() + 165, packet.begin() + 208);

            // chunk with chunk header from 208 till end;
            std::vector<uint8_t> chunkData(packet.begin() + 208, packet.end());
            // std::cout<<"ChunkData size"<<chunkData.size()<<std::endl;
            std::vector<uint8_t> merkleLeafHash = computeHash(chunkData);

            std::vector<std::vector<uint8_t>> siblingHashes;
            // sibling hashes 20 Bytes each, total 5 hashes
            for (size_t j = 0; j < 100; j += 20) {
                siblingHashes.push_back(std::vector<uint8_t>(packet.begin() + j, packet.begin() + j + 20));
            }

            uint8_t leafIndex = packet[228]; // Chunk Merkle leaf index at 228
            // std::cout<<"Chunk Merkle Leaf index"<<(int)packet[228]<<std::endl;

            // Reconstructing Merkle root for this particular chunk;
            std::vector<uint8_t> currentHash = merkleLeafHash;
            size_t idx = leafIndex;
            for (size_t j = 0; j < siblingHashes.size(); ++j) {
                std::vector<uint8_t> concat;
                if(idx%2==0){
                    concat.insert(concat.end(), currentHash.begin(), currentHash.end());
                    concat.insert(concat.end(), siblingHashes[j].begin(), siblingHashes[j].end());
                }else{
                    concat.insert(concat.end(), siblingHashes[j].begin(), siblingHashes[j].end());
                    concat.insert(concat.end(), currentHash.begin(), currentHash.end());
                }
                idx/=2;
                currentHash=computeHash(concat);
            }
            std::vector<uint8_t> merkleRoot = currentHash;
            // std::cout<<"Merkle Root: ";
            // for(int i=0;i<merkleRoot.size();i++){
            //     std::cout<<(int)merkleRoot[i];
            // }
            // std::cout<<std::endl;

            // Concatenating header data with Merkle root for signature verification
            std::vector<uint8_t> dataToVerify = headerData;
            dataToVerify.insert(dataToVerify.end(), merkleRoot.begin(), merkleRoot.end());

            bool signatureValid=false;
            signatureValid = verifier.verifySignature(dataToVerify, signature);
            // std::cout<<"Signature verification"<<std::endl;

            if (!signatureValid) {
                std::lock_guard<std::mutex> lock(coutMutex);
                std::cout << "Signature verification failed for packet with leaf index " << (int)leafIndex << "\n";
                localValid = false;
            } else {
                // std::cout << "Signature and Merkle proof verified for leaf index " << (int)leafIndex << "\n";
                uint16_t chunkId = (static_cast<uint16_t>(packet[230]) << 8) | packet[231]; // Chunk ID at 230-231
                // std::cout << chunkId << " -- " << (int)leafIndex << std::endl;

                // Extract and save payload (232 to end) (Just for testing)
                // std::string payload(packet.begin() + 232, packet.end());
                // std::string filename = "chunk_" + std::to_string(chunkId) + "_leaf_" + std::to_string(leafIndex) + ".txt";
                // std::ofstream outFile(filename);
                // if (outFile.is_open()) {
                //     outFile << payload;
                //     outFile.close();
                //     std::cout << "Payload saved to " << filename << std::endl;
                // } else {
                //     std::cout << "Failed to open file " << filename << std::endl;
                // }
            }
        }

        std::lock_guard<std::mutex> lock(allValidMutex);
        allValid = allValid && localValid;
    };

    for (unsigned int t = 0; t < maxThreads; ++t) {
        size_t startIdx = t * packetsPerThread;
        size_t endIdx = std::min(startIdx + packetsPerThread, packetCount);
        if (startIdx >= endIdx) break;
        threads.emplace_back(worker, startIdx, endIdx);
    }

    for (auto& th : threads) {
        th.join();
    }

    if (allValid) {
        std::lock_guard<std::mutex> lock(coutMutex);
        std::cout << "All packets validated successfully\n";
    } else {
        std::lock_guard<std::mutex> lock(coutMutex);
        std::cout << "Some packets failed validation, discarding block\n";
    }

    stored_packets.erase(block_hash);// clear the packets after processing (ideally, only after successfull processing)

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "Time taken to process Packets: " << duration.count() << " ms" << std::endl;
}

void Validator::printPackets(const std::vector<uint8_t>& block_hash){
    std::vector<std::vector<uint8_t>> sortedPackets = stored_packets[block_hash];
    std::sort(sortedPackets.begin(), sortedPackets.end(), PacketComparator());
    uint32_t total_block_length = (static_cast<uint32_t>(sortedPackets[0][204]) << 24) |
                                 (static_cast<uint32_t>(sortedPackets[0][205]) << 16) |
                                 (static_cast<uint32_t>(sortedPackets[0][206]) << 8)  |
                                 (static_cast<uint32_t>(sortedPackets[0][207]));
    std::cout << "Total block length: " << total_block_length << " bytes\n";
    static size_t total_bytes_written = 0;

    std::cout << "\n";
    std::ofstream outFile("all_chunks.txt", std::ios::out);
    if(outFile.is_open()){

        for (const auto& packet : sortedPackets) {
            uint8_t leafIndex = packet[228];
            uint16_t chunkId = (static_cast<uint16_t>(packet[230]) << 8) | packet[231];
            // std::cout << chunkId << " -- "<< (int)leafIndex << std::endl;
    
            size_t payload_start = 232;
            size_t available_length = packet.end() - (packet.begin() + payload_start);
            size_t bytes_to_write = std::min(available_length, total_block_length - total_bytes_written);
    
            if (bytes_to_write > 0 && total_bytes_written < total_block_length) {
                std::string payload(packet.begin() + payload_start, packet.begin() + payload_start + bytes_to_write);
                outFile << payload;
                total_bytes_written += bytes_to_write;
                outFile.flush();
                std::cout << "Wrote " << bytes_to_write << " bytes, total: " << total_bytes_written << "\n";
            } else if (total_bytes_written >= total_block_length) {
                std::cout << "Reached total block length limit of " << total_block_length << " bytes\n";
            }
        }
        outFile.close();
        stored_packets.clear();
    }else{
        std::cout << "Failed to open file all_chunks.txt" << std::endl;
    }
}