#include "Validator.h"
#include <iostream>
#include <thread>
#include "../leader/UdpSender.h"
#include "UdpReceiver.h"
#include <openssl/sha.h>
#include <openssl/evp.h> // For signature verification
#include <openssl/ec.h>  // For ECDSA
#include <openssl/err.h> 
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <algorithm>
#include <fstream>

// Helper function to compute SHA-256 hash
std::vector<uint8_t> computeHash(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> digest(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), digest.data());
    return std::vector<uint8_t>(digest.begin(), digest.begin()+20);
}

Validator::Validator(std::string addr, uint16_t p, double s) : address(addr), port(p), stake(s) {
    this->other_validators = {
        {"127.0.0.1", 9001, 0.4},
        {"127.0.0.1", 9002, 0.3},
        {"127.0.0.1", 9003, 0.2},
        {"127.0.0.1", 9004, 0.1}
    };
    std::cout << "Validator constructed at " << address << ":" << port << "\n";
}

Validator::~Validator() {
    std::cout << "Validator at " << address << ":" << port << " destroyed\n"; // Debug destructor
}

void Validator::run() {
    std::cout<<"Listening to packets"<<std::endl;
    UdpReceiver receiver(address, port);

    // while (true) {
    //     std::vector<uint8_t> packet = receiver.receivePacket();
    //     receivePacket(packet);
    // }
    while (true) {
        std::vector<uint8_t> packet = receiver.receivePacket();
        if (!packet.empty()) { // Packet received
            receivePacket(packet);
        }
    }
}

void Validator::receivePacket(const std::vector<uint8_t>& packet) {
    if (packet.size() < 68) return;
    // stored_packets.push_back(packet);
    stored_packets[std::vector<uint8_t>(packet.begin() + 184, packet.begin() + 204)].push_back(packet); // Hash as key

    // std::cout<<stored_packets.size()<<std::endl;
    // Process if enough packets (e.g., 12 for 4 chunks with redundancy 2 + 4 backups)
    if (packet[167] & 0x80) {
        std::cout<<"Broadcast"<<std::endl;
        rebroadcastPacket(packet);
    }else{
        std::cout<<"2nd Layer"<<std::endl;
    }

    if (stored_packets[std::vector<uint8_t>(packet.begin() + 184, packet.begin() + 204)].size() >= 32) {
        processPackets(std::vector<uint8_t>(packet.begin() + 184, packet.begin() + 204));
    }

    // Re-broadcast if Broadcast flag is 1
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

std::vector<uint8_t> signData(const std::vector<uint8_t>& toHash, const std::string& privateKeyFile) {
    // Compute SHA-256 hash of toHash
    std::vector<uint8_t> hashDigest(SHA256_DIGEST_LENGTH);
    SHA256(toHash.data(), toHash.size(), hashDigest.data());

    // Load private key from PEM file
    FILE* fp = fopen(privateKeyFile.c_str(), "r");
    if (!fp) throw std::runtime_error("Failed to open private key file");
    EC_KEY* ecKey = PEM_read_ECPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!ecKey) throw std::runtime_error("Failed to read private key");

    // Sign the hash
    ECDSA_SIG* sig = ECDSA_do_sign(hashDigest.data(), SHA256_DIGEST_LENGTH, ecKey);
    if (!sig) {
        EC_KEY_free(ecKey);
        throw std::runtime_error("Signature failed");
    }

    // Serialize signature (r || s) padded to 32 bytes each
    const BIGNUM* r;
    const BIGNUM* s;
    ECDSA_SIG_get0(sig, &r, &s);

    std::vector<uint8_t> signature(65, 0); // 32 bytes r + 32 bytes s + 1 byte recovery ID
    BN_bn2binpad(r, &signature[0], 32);
    BN_bn2binpad(s, &signature[32], 32);
    signature[64] = 0; // Recovery ID (not used here)

    // Cleanup
    ECDSA_SIG_free(sig);
    EC_KEY_free(ecKey);

    return signature;
}

struct PacketComparator {
    bool operator()(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) const {
        uint16_t chunkIdA = (static_cast<uint16_t>(a[230]) << 8) | a[231]; // Chunk ID at 230-231
        uint16_t chunkIdB = (static_cast<uint16_t>(b[230]) << 8) | b[231];
        if (chunkIdA != chunkIdB) return chunkIdA < chunkIdB;
        return a[228] < b[228]; // Chunk Merkle leaf index at 228
    }
};

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <vector>
#include <stdexcept>
#include <iostream>
#include <fstream>

// bool verifySignature(const std::vector<uint8_t>& signature, const std::vector<uint8_t>& dataToVerify, const std::string& publicKeyFile) {
//     // std::cout<<dataToVerify.size()<<"  fjalsdfjalsdf"<<std::endl;
//     std::vector<uint8_t> hashDigest(SHA256_DIGEST_LENGTH);
//     SHA256(dataToVerify.data(), dataToVerify.size(), hashDigest.data());

//     // Load public key from PEM file
//     FILE* fp = fopen(publicKeyFile.c_str(), "r");
//     if (!fp) throw std::runtime_error("Failed to open public key file: " + publicKeyFile);
//     EVP_PKEY* pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
//     fclose(fp);
//     if (!pkey) throw std::runtime_error("Failed to read public key from: " + publicKeyFile);

//     // Verify signature
//     EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
//     if (!mdctx) {
//         EVP_PKEY_free(pkey);
//         throw std::runtime_error("Failed to create MD context");
//     }

//     if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
//         ERR_print_errors_fp(stderr); // Print OpenSSL errors
//         EVP_MD_CTX_free(mdctx);
//         EVP_PKEY_free(pkey);
//         throw std::runtime_error("Failed to initialize verification context");
//     }

//     if (EVP_DigestVerifyUpdate(mdctx, dataToVerify.data(), dataToVerify.size()) <= 0) {
//         ERR_print_errors_fp(stderr); // Print OpenSSL errors
//         EVP_MD_CTX_free(mdctx);
//         EVP_PKEY_free(pkey);
//         throw std::runtime_error("Failed to update verification context");
//     }

//     int result = EVP_DigestVerifyFinal(mdctx, signature.data(), signature.size());
//     if (result <= 0) {
//         ERR_print_errors_fp(stderr); // Print OpenSSL errors
//     }
//     EVP_MD_CTX_free(mdctx);
//     EVP_PKEY_free(pkey);

//     if (result == 1) {
//         return true;
//     } else if (result == 0) {
//         return false;
//     } else {
//         throw std::runtime_error("Verification failed with error: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
//     }
// }

#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <stdexcept>
#include <vector>
#include <string>

bool verifySignature(const std::vector<uint8_t>& toHash,
                     const std::vector<uint8_t>& signature,
                     const std::string& publicKeyFile) {
    if (signature.size() < 64) {
        throw std::runtime_error("Invalid signature size");
    }

    // Compute SHA-256 hash of toHash
    std::vector<uint8_t> hashDigest(SHA256_DIGEST_LENGTH);
    SHA256(toHash.data(), toHash.size(), hashDigest.data());

    // Load public key from PEM file
    FILE* fp = fopen(publicKeyFile.c_str(), "r");
    if (!fp) throw std::runtime_error("Failed to open public key file");
    EC_KEY* ecKey = PEM_read_EC_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!ecKey) throw std::runtime_error("Failed to read public key");

    // Extract r and s from signature vector
    BIGNUM* r = BN_bin2bn(&signature[0], 32, NULL);
    BIGNUM* s = BN_bin2bn(&signature[32], 32, NULL);
    if (!r || !s) {
        EC_KEY_free(ecKey);
        BN_free(r);
        BN_free(s);
        throw std::runtime_error("Failed to create BIGNUMs for r and s");
    }

    // Recreate ECDSA_SIG structure
    ECDSA_SIG* sig = ECDSA_SIG_new();
    if (!sig) {
        EC_KEY_free(ecKey);
        BN_free(r);
        BN_free(s);
        throw std::runtime_error("Failed to allocate ECDSA_SIG");
    }

    if (ECDSA_SIG_set0(sig, r, s) != 1) {
        EC_KEY_free(ecKey);
        ECDSA_SIG_free(sig);
        BN_free(r);
        BN_free(s); // Only if set0 fails, else ownership transferred
        throw std::runtime_error("Failed to set r and s in signature");
    }

    // Verify the signature
    int verifyStatus = ECDSA_do_verify(hashDigest.data(), SHA256_DIGEST_LENGTH, sig, ecKey);

    // Cleanup
    ECDSA_SIG_free(sig);
    EC_KEY_free(ecKey);

    return verifyStatus == 1; // 1 = valid, 0 = invalid, -1 = error
}


// const std::vector<uint8_t> LEADER_PUBLIC_KEY = {
//     0x04,
//     0x67, 0xa1, 0xdf, 0x8f, 0x57, 0x11, 0x2c, 0xd9,
//     0x35, 0xc3, 0x7a, 0x4e, 0x08, 0x6d, 0x92, 0x6a,
//     0x82, 0x42, 0x7a, 0xbe, 0xf1, 0xd1, 0x69, 0x8b,
//     0xd6, 0xb4, 0xf2, 0x6b, 0x77, 0xc1, 0xfa, 0x02,
//     0x27, 0x8f, 0x61, 0x5b, 0xba, 0x66, 0x42, 0xb1,
//     0x8e, 0x0b, 0xb7, 0xb2, 0xe3, 0xc4, 0x12, 0x8c,
//     0x1b, 0xe0, 0x9d, 0xaa, 0x83, 0x6e, 0x1e, 0x71,
//     0x42, 0x4c, 0x57, 0x8e, 0x4d, 0x26, 0x2b, 0xdf,
//     0x30
// };

void Validator::processPackets(const std::vector<uint8_t>& block_hash) {
    printPackets(block_hash);

    std::cout << "Validator at " << address << ":" << port << " processing " << stored_packets[block_hash].size() << " packets for block hash: ";
    // for (uint8_t byte : block_hash) std::cout << std::hex << (int)byte << " ";

    // std::vector<std::vector<uint8_t>> sortedPackets = stored_packets[block_hash];
    // std::sort(sortedPackets.begin(), sortedPackets.end(), PacketComparator());

    // EVP_PKEY* publicKey = loadPublicKey(LEADER_PUBLIC_KEY);
    // if (!publicKey) {
    //     std::cout << "Error: Failed to load public key\n";
    //     stored_packets.erase(block_hash);
    //     return;
    // }

    bool allValid = true;
    for (auto& packet : stored_packets[block_hash]) {
        packet[167] |= 0x80;
        // Extract signature (100-164) and header data (165-207)
        std::vector<uint8_t> signature(packet.begin() + 100, packet.begin() + 165); // 65 bytes
        std::vector<uint8_t> headerData(packet.begin() + 165, packet.begin() + 208); // 43 bytes

        // Extract chunk data (208 to end) and compute leaf hash
        std::vector<uint8_t> chunkData(packet.begin() + 208, packet.end());
        std::cout<<"ChunkData size"<<chunkData.size()<<std::endl;
        std::vector<uint8_t> merkleLeafHash = computeHash(chunkData);
        // for(int i=0;i<merkleLeafHash.size();i++){
        //     std::cout<<(int)merkleLeafHash[i];
        // }
        // std::cout<<"Hash Finished"<<std::endl;
        // Extract Merkle proof (0-99 bytes)
        std::vector<std::vector<uint8_t>> siblingHashes;
        for (size_t i = 0; i < 100; i += 20) { // 100 bytes, 32-byte hashes (adjust if 20-byte)
            siblingHashes.push_back(std::vector<uint8_t>(packet.begin() + i, packet.begin() + i + 20));
        }

        std::cout<<"Sibling Hashes"<<std::endl;
        for(int i=0;i<siblingHashes.size();i++){
            for(int j=0;j<20;j++){
                std::cout<<(int)siblingHashes[i][j];
            }
            std::cout<<std::endl;
        }
        uint8_t leafIndex = packet[228]; // Chunk Merkle leaf index at 228
        std::cout<<"Chunk Merkle Leaf index"<<(int)packet[228]<<std::endl;
        // Reconstruct Merkle root for this chunk
        std::vector<uint8_t> currentHash = merkleLeafHash;
        size_t idx = leafIndex;
        for (size_t i = 0; i < siblingHashes.size(); ++i) {
            std::vector<uint8_t> concat;
            if(idx%2==0){
                concat.insert(concat.end(), currentHash.begin(), currentHash.end());
                concat.insert(concat.end(), siblingHashes[i].begin(), siblingHashes[i].end());
            }else{
                concat.insert(concat.end(), siblingHashes[i].begin(), siblingHashes[i].end());
                concat.insert(concat.end(), currentHash.begin(), currentHash.end());
            }
            idx/=2;
            currentHash=computeHash(concat);
        }
        std::vector<uint8_t> merkleRoot = currentHash;
        std::cout<<"Merkle Root: ";
        for(int i=0;i<merkleRoot.size();i++){
            std::cout<<(int)merkleRoot[i];
        }
        std::cout<<std::endl;
        // Concatenate header data with Merkle root for signature verification
        std::vector<uint8_t> dataToVerify = headerData;
        dataToVerify.insert(dataToVerify.end(), merkleRoot.begin(), merkleRoot.end());
        // std::cout<<"TO HASH"<<std::endl;
        // for(int i=0;i<dataToVerify.size();i++){
        //     std::cout<<(int)dataToVerify[i];
        // }
        // std::cout<<"TO HASH END"<<std::endl;

        bool signatureValid=false;
        signatureValid = verifySignature(dataToVerify, signature, "../ec-secp256k1-pub-key.pem");
        std::cout<<"Signature verification"<<std::endl;

        if (!signatureValid) {
            std::cout << "Signature verification failed for packet with leaf index " << (int)leafIndex << "\n";
            allValid = false;
        } else {
            std::cout << "Signature and Merkle proof verified for leaf index " << (int)leafIndex << "\n";
            uint8_t leafIndex = packet[228]; // Chunk Merkle leaf index at 228
            uint16_t chunkId = (static_cast<uint16_t>(packet[230]) << 8) | packet[231]; // Chunk ID at 230-231
            std::cout << chunkId << " -- " << (int)leafIndex << std::endl;

            // Extract and save payload (208 to end)
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

    if (allValid) {
        std::cout << "All packets validated successfully\n";
    } else {
        std::cout << "Some packets failed validation, discarding block\n";
    }

    stored_packets.erase(block_hash); // Clear only this block's packets
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
            std::cout << chunkId << " -- "<< (int)leafIndex << std::endl;
    
            size_t payload_start = 232;
            size_t available_length = packet.end() - (packet.begin() + payload_start);
            size_t bytes_to_write = std::min(available_length, total_block_length - total_bytes_written);
    
            if (bytes_to_write > 0 && total_bytes_written < total_block_length) {
                std::string payload(packet.begin() + payload_start, packet.begin() + payload_start + bytes_to_write);
                outFile << payload;
                total_bytes_written += bytes_to_write;
                outFile.flush(); // Ensure data is written
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