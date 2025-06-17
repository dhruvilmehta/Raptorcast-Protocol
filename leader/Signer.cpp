#include "Signer.h"
#include <openssl/sha.h>
#include <stdexcept>
#include <iostream>
#include <openssl/pem.h>

Signer::Signer(const std::string& privateKeyFile) : ecKey(nullptr) {
    // Load private key from PEM file once
    FILE* fp = fopen(privateKeyFile.c_str(), "r");
    if (!fp) throw std::runtime_error("Failed to open private key file");
    ecKey = PEM_read_ECPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!ecKey) throw std::runtime_error("Failed to read private key");
}

Signer::~Signer() {
    if (ecKey) EC_KEY_free(ecKey); // Cleanup
}

std::vector<uint8_t> Signer::signData(const std::vector<uint8_t>& toHash) {
    // SHA-256 hash
    std::vector<uint8_t> hashDigest(SHA256_DIGEST_LENGTH);
    SHA256(toHash.data(), toHash.size(), hashDigest.data());

    // Sign the hash
    ECDSA_SIG* sig = ECDSA_do_sign(hashDigest.data(), SHA256_DIGEST_LENGTH, ecKey);
    if (!sig) throw std::runtime_error("Signature failed");

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

    return signature;
}