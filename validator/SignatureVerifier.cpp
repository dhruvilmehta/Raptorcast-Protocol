#include "SignatureVerifier.h"
#include <stdexcept>
#include <iostream>
#include <openssl/pem.h>

SignatureVerifier::SignatureVerifier(const std::string& publicKeyFile) : ecKey(nullptr){
    // via GPT
    // Load public key from PEM file
    // std::cout<<publicKeyFile.c_str()<<std::endl;
    FILE* fp = fopen(publicKeyFile.c_str(), "r");
    if (!fp) throw std::runtime_error("Failed to open public file");
    ecKey = PEM_read_EC_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!ecKey) throw std::runtime_error("Failed to read public key");
}

SignatureVerifier::~SignatureVerifier() {
    if (ecKey) EC_KEY_free(ecKey); // Cleanup
}

bool SignatureVerifier::verifySignature(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature){
    if (signature.size() < 64) {
        throw std::runtime_error("Invalid signature size");
    }

    // computing sha256 hash
    std::vector<uint8_t> hashDigest(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hashDigest.data());

    // Extract r and s from signature vector
    BIGNUM* r = BN_bin2bn(&signature[0], 32, NULL);
    BIGNUM* s = BN_bin2bn(&signature[32], 32, NULL);
    if (!r || !s) {
        // EC_KEY_free(ecKey);
        // BN_free(r);
        // BN_free(s);
        throw std::runtime_error("Failed to create BIGNUMs for r and s");
    }

    // Recreate ECDSA_SIG structure
    ECDSA_SIG* sig = ECDSA_SIG_new();
    if (!sig) {
        // EC_KEY_free(ecKey);
        // BN_free(r);
        // BN_free(s);
        throw std::runtime_error("Failed to allocate ECDSA_SIG");
    }

    if (ECDSA_SIG_set0(sig, r, s) != 1) {
        // EC_KEY_free(ecKey);
        // ECDSA_SIG_free(sig);
        // BN_free(r);
        // BN_free(s); // Only if set0 fails, else ownership transferred
        throw std::runtime_error("Failed to set r and s in signature");
    }

    // Verify the signature
    int verifyStatus = ECDSA_do_verify(hashDigest.data(), SHA256_DIGEST_LENGTH, sig, ecKey);

    return verifyStatus == 1; // 1 = valid, 0 = invalid, -1 = error
}