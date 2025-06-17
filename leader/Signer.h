#ifndef SIGNER_H
#define SIGNER_H

#include <vector>
#include <string>
#include <openssl/ec.h>

class Signer {
public:
    Signer(const std::string& privateKeyFile);
    ~Signer();
    std::vector<uint8_t> signData(const std::vector<uint8_t>& toHash);

private:
    EC_KEY* ecKey;
};

#endif