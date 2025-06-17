#ifndef SIGNER_H
#define SIGNER_H

#include <vector>
#include <string>
#include <openssl/ec.h>

class SignatureVerifier {
public:
    SignatureVerifier(const std::string& publicKeyFile);
    ~SignatureVerifier();
    bool verifySignature(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature);

private:
    EC_KEY* ecKey;
};

#endif