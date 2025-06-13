#include "HeaderBuilder.h"
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <stdexcept>
#include <cstring>
#include <chrono>
#include "ProcessManager.h"
#include <openssl/pem.h>
#include <iostream>

// // ✅ Leader's 32-byte private key (hex: 1...32)
// const std::vector<uint8_t> LEADER_PRIVATE_KEY = {
//     0x1e, 0x99, 0x02, 0x43, 0x79, 0x28, 0xaf, 0xc2,
//     0x55, 0xd1, 0x01, 0xf3, 0xa8, 0x14, 0xe4, 0x5c,
//     0xf9, 0x61, 0x18, 0xf3, 0x0b, 0x28, 0xbd, 0x10,
//     0x89, 0xc3, 0x3f, 0x91, 0xde, 0x64, 0x7c, 0xab
// };

// // ✅ Corresponding 65-byte uncompressed public key (0x04 || X || Y)
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

// Helper: Big-endian serialization
template <typename T>
void appendBigEndian(std::vector<uint8_t>& out, T value, size_t byteSize) {
    for (int i = byteSize - 1; i >= 0; --i) {
        out.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xFF));
    }
}

std::vector<uint8_t> HeaderBuilder::build(
    const std::vector<uint8_t>& merkleRoot,
    const std::vector<uint8_t>& blockHashFirst20,
    uint64_t epoch,
    uint64_t timestampMillis,
    uint16_t version,
    bool isBroadcast,
    uint32_t blockLength
) {
    if (merkleRoot.size() != 20) throw std::invalid_argument("Merkle root must be 20 bytes");
    if (blockHashFirst20.size() != 20) throw std::invalid_argument("Block hash must be 20 bytes");
    // if (privateKey.size() != 32) throw std::invalid_argument("Private key must be 32 bytes");

    std::vector<uint8_t> headerFields;

    // 2 bytes: version (big endian)
    appendBigEndian(headerFields, version, 2);

    // 1 byte: 1 bit broadcast, 7 bits Merkle depth (assumed 5)
    uint8_t broadcastAndDepth = ((isBroadcast ? 1 : 0) << 7) | (5 & 0x7F);
    headerFields.push_back(broadcastAndDepth);

    // 8 bytes: epoch (big endian)
    appendBigEndian(headerFields, epoch, 8);

    // 8 bytes: timestamp (ms) (big endian)
    appendBigEndian(headerFields, timestampMillis, 8);

    // 20 bytes: block proposal hash (first 20 bytes)
    headerFields.insert(headerFields.end(), blockHashFirst20.begin(), blockHashFirst20.end());

    // 4 bytes: block length (big endian)
    appendBigEndian(headerFields, blockLength, 4);

    // Hash(headerFields || merkleRoot)
    std::vector<uint8_t> toHash(headerFields);
    toHash.insert(toHash.end(), merkleRoot.begin(), merkleRoot.end());
    // std::cout<<"TO HASH"<<std::endl;
    // for(int i=0;i<toHash.size();i++){
    //     std::cout<<(int)toHash[i];
    // }
    // std::cout<<"TO HASH END"<<std::endl;
    uint8_t hashDigest[SHA256_DIGEST_LENGTH];
    SHA256(toHash.data(), toHash.size(), hashDigest);
    std::vector<uint8_t> signature = signData(toHash, "../ec-secp256k1-priv-key.pem");
    std::cout<<"WANTED SIGNATURE\n"<<"SIZE"<<signature.size()<<std::endl;
    for(int i=0;i<signature.size();i++){
        std::cout<<(int)signature[i];
    }
    std::cout<<"WANTED SIGNATURE END"<<std::endl;
    // // Sign using ECDSA with secp256k1
    // EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_secp256k1);
    // BIGNUM* priv = BN_bin2bn(privateKey.data(), privateKey.size(), nullptr);
    // EC_KEY_set_private_key(ecKey, priv);

    // ECDSA_SIG* sig = ECDSA_do_sign(hashDigest, SHA256_DIGEST_LENGTH, ecKey);
    // if (!sig) throw std::runtime_error("Signature failed");

    // // Serialize signature (r || s) padded to 32 bytes each
    // const BIGNUM* r;
    // const BIGNUM* s;
    // ECDSA_SIG_get0(sig, &r, &s);

    // std::vector<uint8_t> signature(65, 0);
    // BN_bn2binpad(r, &signature[0], 32);
    // BN_bn2binpad(s, &signature[32], 32);
    // signature[64] = 0;  // recovery ID = 0 (not used)

    // // Cleanup
    // ECDSA_SIG_free(sig);
    // EC_KEY_free(ecKey);
    // BN_free(priv);

    // Assemble final header
    std::vector<uint8_t> finalHeader;
    finalHeader.insert(finalHeader.end(), signature.begin(), signature.end());   // 65 bytes
    finalHeader.insert(finalHeader.end(), headerFields.begin(), headerFields.end()); // 43 bytes

    if (finalHeader.size() != 108)
        throw std::runtime_error("Header must be 108 bytes");

    return finalHeader;
}

std::vector<std::vector<uint8_t>> HeaderBuilder::buildGroupHeaders(std::vector<std::vector<uint8_t>> merkleRoots, std::size_t blockSize, std::vector<uint8_t> blockHash){
    std::vector<std::vector<uint8_t>> groupHeaders;
    uint64_t epoch = 1;
    uint16_t version = 1;
    bool isBroadcast = true;
    uint32_t blockLength = static_cast<uint32_t>(blockSize);
    
    uint64_t timestampMillis = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    
    for (const auto& merkleRoot : merkleRoots) {
        std::cout<<"Merkle Root: "<<std::endl;
        for(int i=0;i<merkleRoot.size();i++){
            std::cout<<(int)merkleRoot[i];
        }
        std::cout<<std::endl;
        std::vector<uint8_t> header = HeaderBuilder::build(
            merkleRoot,
            blockHash,
            epoch,
            timestampMillis,
            version,
            isBroadcast,
            blockLength
        );
    
        groupHeaders.push_back(header);
    }

    return groupHeaders;
}