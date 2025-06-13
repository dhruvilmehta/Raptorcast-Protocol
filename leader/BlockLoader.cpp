#include "BlockLoader.h"
#include <fstream>
#include <sstream>
#include <iostream>

std::vector<uint8_t> BlockLoader::loadTextBlock(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    std::vector<uint8_t> data;

    if (!file.is_open()) {
        std::cerr << "Error: Failed to open block file: " << filename << std::endl;
        return data;
    }

    // reading the file into string stream. file is mimicking the block transactions
    std::ostringstream buffer;
    buffer << file.rdbuf();

    //converting the string into vector of uint_8 for processing.
    std::string content = buffer.str();
    data.assign(content.begin(), content.end());

    return data;
}
