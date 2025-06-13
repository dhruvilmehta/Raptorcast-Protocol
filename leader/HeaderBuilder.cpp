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

std::vector<uint8_t> signData(const std::vector<uint8_t>& toHash, const std::string& privateKeyFile) {
    // sha256
    std::vector<uint8_t> hashDigest(SHA256_DIGEST_LENGTH);
    SHA256(toHash.data(), toHash.size(), hashDigest.data());

    // from gpt
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

    std::vector<uint8_t> headerFields;

    // version: 2 Bytes big endian
    appendBigEndian(headerFields, version, 2);

    // 1 byte: 1 bit for broadcast bit and 7 bits Merkle depth (merkle depth is 5 as of now, since we are forming groups of 32 each)
    uint8_t broadcastAndDepth = ((isBroadcast ? 1 : 0) << 7) | (5 & 0x7F);
    headerFields.push_back(broadcastAndDepth);

    // 8 bytes: epoch (big endian)
    appendBigEndian(headerFields, epoch, 8);

    // 8 bytes: timestamp (big endian)
    appendBigEndian(headerFields, timestampMillis, 8);

    // 20 bytes: block proposal hash, only first 20 bytes according to the blog
    headerFields.insert(headerFields.end(), blockHashFirst20.begin(), blockHashFirst20.end());

    // 4 bytes: block length (big endian)
    appendBigEndian(headerFields, blockLength, 4);

    // sign(sha256(headerFields + merkleRoot)) // from blog
    std::vector<uint8_t> toHash(headerFields);
    toHash.insert(toHash.end(), merkleRoot.begin(), merkleRoot.end());

    uint8_t hashDigest[SHA256_DIGEST_LENGTH];
    SHA256(toHash.data(), toHash.size(), hashDigest);
    std::vector<uint8_t> signature = signData(toHash, "../ec-secp256k1-priv-key.pem");

    // final header: signature+header fields
    std::vector<uint8_t> finalHeader;
    finalHeader.insert(finalHeader.end(), signature.begin(), signature.end());   // 65 bytes
    finalHeader.insert(finalHeader.end(), headerFields.begin(), headerFields.end()); // 43 bytes

    // header size is 108 Bytes
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
        // std::cout<<"Merkle Root: "<<std::endl;
        // for(int i=0;i<merkleRoot.size();i++){
        //     std::cout<<(int)merkleRoot[i];
        // }
        // std::cout<<std::endl;
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