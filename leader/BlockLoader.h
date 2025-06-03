#pragma once
#include <string>
#include <vector>
#include <cstdint>

class BlockLoader
{
public:
    static std::vector<uint8_t> loadTextBlock(const std::string &filepath);
};
