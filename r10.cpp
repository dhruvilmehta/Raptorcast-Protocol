#include <iostream>
#include <vector>
#include <random>
#include <cstdint>
#include <algorithm>

// Structure to represent a symbol (repair symbol in this case)
struct Symbol {
    std::vector<uint8_t> data; // Symbol data (XOR of source packets)
    std::vector<size_t> indices; // Indices of source symbols XORed to create this symbol
};

// XOR two vectors of uint8_t (byte-wise)
std::vector<uint8_t> xor_vectors(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    std::vector<uint8_t> result(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

// Generate repair symbols using the specified degree distribution
std::vector<Symbol> encode_raptor(const std::vector<std::vector<uint8_t>>& packets, size_t num_repair, size_t symbol_size) {
    std::vector<Symbol> symbols;
    std::random_device rd;
    std::mt19937 gen(rd());

    std::vector<std::pair<size_t, double>> degree_dist = {
        {1, 0.009},   // 0.9% chance for degree 1
        {2, 0.458},   // 45.8% chance for degree 2
        {3, 0.233},   // 23.3% chance for degree 3
        {4, 0.118},   // 11.8% chance for degree 4
        {8, 0.082},   // 8.2% chance for degree 8
        {9, 0.060},   // 6.0% chance for degree 9
        {19, 0.020},  // 2.0% chance for degree 19
        {66, 0.010},  // 1.0% chance for degree 66
        {100, 0.010}  // 1.0% chance for degree 100
    };


    // Create a discrete distribution for selecting degrees
    std::vector<double> weights;
    for (const auto& pair : degree_dist) {
        weights.push_back(pair.second);
    }
    std::discrete_distribution<size_t> degree_selector(weights.begin(), weights.end());

    // Generate repair symbols
    for (size_t i = 0; i < num_repair; ++i) {
        Symbol repair;
        repair.data = std::vector<uint8_t>(symbol_size, 0); // Initialize to zeros
        repair.indices.clear();

        // Select degree based on distribution
        size_t degree_idx = degree_selector(gen);
        size_t degree = degree_dist[degree_idx].first;

        // Ensure degree does not exceed number of packets
        degree = std::min(degree, packets.size());

        // Randomly select 'degree' source symbols
        std::vector<size_t> indices(packets.size());
        for (size_t j = 0; j < packets.size(); ++j) {
            indices[j] = j;
        }
        std::shuffle(indices.begin(), indices.end(), gen);
        std::vector<size_t> selected_indices(indices.begin(), indices.begin() + degree);

        // XOR the selected source symbols
        for (size_t idx : selected_indices) {
            repair.data = xor_vectors(repair.data, packets[idx]);
        }
        repair.indices = selected_indices;
        symbols.push_back(repair);
    }

    return symbols;
}

// Decode by recovering missing source symbols (unchanged)
std::vector<std::vector<uint8_t>> decode_raptor(const std::vector<Symbol>& received, size_t num_source, size_t symbol_size) {
    std::vector<std::vector<uint8_t>> recovered(num_source, std::vector<uint8_t>(symbol_size, 0));
    std::vector<bool> have_symbol(num_source, false);
    size_t recovered_count = 0;

    // Step 1: Collect known source symbols (if any are included)
    for (const auto sym : received) {
        if (sym.indices.size() == 1) { // Source symbol
            size_t idx = sym.indices[0];
            if (!have_symbol[idx]) {
                recovered[idx] = sym.data;
                have_symbol[idx] = true;
                ++recovered_count;
            }
        }
    }

    // Step 2: Iterative decoding using repair symbols
    bool progress = true;
    while (progress && recovered_count < num_source) {
        progress = false;
        for (const auto& sym : received) {
            if (sym.indices.size() <= 1) continue; // Skip source symbols or used repair symbols

            // Count known source symbols in this repair symbol
            std::vector<size_t> unknown_indices;
            size_t known_idx = -1;
            int known_count = 0;
            for (size_t idx : sym.indices) {
                if (have_symbol[idx]) {
                    ++known_count;
                    known_idx = idx;
                } else {
                    unknown_indices.push_back(idx);
                }
            }

            // If repair symbol has exactly one unknown source symbol, recover it
            if (unknown_indices.size() == 1) {
                size_t target_idx = unknown_indices[0];
                if (!have_symbol[target_idx]) {
                    recovered[target_idx] = sym.data; // Start with repair symbol data
                    for (size_t idx : sym.indices) {
                        if (idx != target_idx) {
                            recovered[target_idx] = xor_vectors(recovered[target_idx], recovered[idx]);
                        }
                    }
                    have_symbol[target_idx] = true;
                    ++recovered_count;
                    progress = true;
                }
            }
        }
    }

    // Check if all source symbols were recovered
    std::cout << recovered_count << " -------" << std::endl;
    if (recovered_count != num_source) {
        throw std::runtime_error("Failed to recover all source symbols");
    }
    return recovered;
}

int main() {
    // Example input: 100 packets, each 8 bytes
    std::vector<std::vector<uint8_t>> packets = {
        {1, 2, 3, 4, 5, 6, 7, 8},
        {9, 10, 11, 12, 13, 14, 15, 16},
        {17, 18, 19, 20, 21, 22, 23, 24},
        {25, 26, 27, 28, 29, 30, 31, 32},
        {1, 2, 3, 4, 5, 6, 7, 8},
        {9, 10, 11, 12, 13, 14, 15, 16},
        {17, 18, 19, 20, 21, 22, 23, 24},
        {25, 26, 27, 28, 29, 30, 31, 32},
        {1, 2, 3, 4, 5, 6, 7, 8},
        {9, 10, 11, 12, 13, 14, 15, 16},
        {17, 18, 19, 20, 21, 22, 23, 24},
        {25, 26, 27, 28, 29, 30, 31, 32},
        {1, 2, 3, 4, 5, 6, 7, 8},
        {9, 10, 11, 12, 13, 14, 15, 16},
        {17, 18, 19, 20, 21, 22, 23, 24},
        {25, 26, 27, 28, 29, 30, 31, 32},
        {1, 2, 3, 4, 5, 6, 7, 8},
        {9, 10, 11, 12, 13, 14, 15, 16},
        {17, 18, 19, 20, 21, 22, 23, 24},
        {25, 26, 27, 28, 29, 30, 31, 32},
        {1, 2, 3, 4, 5, 6, 7, 8},
        {9, 10, 11, 12, 13, 14, 15, 16},
        {17, 18, 19, 20, 21, 22, 23, 24},
        {25, 26, 27, 28, 29, 30, 31, 32},
        {1, 2, 3, 4, 5, 6, 7, 8},
        {9, 10, 11, 12, 13, 14, 15, 16},
        {17, 18, 19, 20, 21, 22, 23, 24},
        {25, 26, 27, 28, 29, 30, 31, 32},
        {1, 2, 3, 4, 5, 6, 7, 8},
        {9, 10, 11, 12, 13, 14, 15, 16},
        {17, 18, 19, 20, 21, 22, 23, 24},
        {25, 26, 27, 28, 29, 30, 31, 32},
        {1, 2, 3, 4, 5, 6, 7, 8},
        {9, 10, 11, 12, 13, 14, 15, 16},
        {17, 18, 19, 20, 21, 22, 23, 24},
        {25, 26, 27, 28, 29, 30, 31, 32},
        {1, 2, 3, 4, 5, 6, 7, 8},
        {9, 10, 11, 12, 13, 14, 15, 16},
        {17, 18, 19, 20, 21, 22, 23, 24},
        {25, 26, 27, 28, 29, 30, 31, 32},
        {1, 2, 3, 4, 5, 6, 7, 8},
        {9, 10, 11, 12, 13, 14, 15, 16},
        {17, 18, 19, 20, 21, 22, 23, 24},
        {25, 26, 27, 28, 29, 30, 31, 32},
        {1, 2, 3, 4, 5, 6, 7, 8},
        {9, 10, 11, 12, 13, 14, 15, 16},
        {17, 18, 19, 20, 21, 22, 23, 24},
        {25, 26, 27, 28, 29, 30, 31, 32},
        {1, 2, 3, 4, 5, 6, 7, 8},
        {9, 10, 11, 12, 13, 14, 15, 16},
        {17, 18, 19, 20, 21, 22, 23, 24},
        {25, 26, 27, 28, 29, 30, 31, 32},
        {1, 2, 3, 4, 5, 6, 7, 8},
        {9, 10, 11, 12, 13, 14, 15, 16},
        {17, 18, 19, 20, 21, 22, 23, 24},
        {25, 26, 27, 28, 29, 30, 31, 32},
        {1, 2, 3, 4, 5, 6, 7, 8},
        {9, 10, 11, 12, 13, 14, 15, 16},
        {17, 18, 19, 20, 21, 22, 23, 24},
        {25, 26, 27, 28, 29, 30, 31, 32},
        {1, 2, 3, 4, 5, 6, 7, 8},
        {9, 10, 11, 12, 13, 14, 15, 16},
        {17, 18, 19, 20, 21, 22, 23, 24},
        {25, 26, 27, 28, 29, 30, 31, 32},
        {1, 2, 3, 4, 5, 6, 7, 8},
        {9, 10, 11, 12, 13, 14, 15, 16},
        {17, 18, 19, 20, 21, 22, 23, 24},
        {25, 26, 27, 28, 29, 30, 31, 32},
        {1, 2, 3, 4, 5, 6, 7, 8},
        {9, 10, 11, 12, 13, 14, 15, 16},
        {17, 18, 19, 20, 21, 22, 23, 24},
        {25, 26, 27, 28, 29, 30, 31, 32},
        {1, 2, 3, 4, 5, 6, 7, 8},
        {9, 10, 11, 12, 13, 14, 15, 16},
        {17, 18, 19, 20, 21, 22, 23, 24},
        {25, 26, 27, 28, 29, 30, 31, 32},
        {1, 2, 3, 4, 5, 6, 7, 8},
        {9, 10, 11, 12, 13, 14, 15, 16},
        {17, 18, 19, 20, 21, 22, 23, 24},
        {25, 26, 27, 28, 29, 30, 31, 32},
        {1, 2, 3, 4, 5, 6, 7, 8},
        {9, 10, 11, 12, 13, 14, 15, 16},
        {17, 18, 19, 20, 21, 22, 23, 24},
        {25, 26, 27, 28, 29, 30, 31, 32},
        {1, 2, 3, 4, 5, 6, 7, 8},
        {9, 10, 11, 12, 13, 14, 15, 16},
        {17, 18, 19, 20, 21, 22, 23, 24},
        {25, 26, 27, 28, 29, 30, 31, 32},
    };
    size_t symbol_size = packets[0].size();
    size_t num_source = packets.size();
    size_t num_repair = 120; // Generate 110 repair symbols
    std::cout<<num_source<<" Data Length"<<std::endl;
    // Encode
    std::vector<Symbol> encoded = encode_raptor(packets, num_repair, symbol_size);
    std::cout << encoded.size() << " --" << std::endl;

    // Print indices of repair symbols
    // for (size_t idx = 0; idx < encoded.size(); ++idx) {
    //     // std::cout << "Repair symbol " << idx << " indices: ";
    //     for (int index : encoded[idx].indices) {
    //         std::cout << index << " ";
    //     }
    //     std::cout << std::endl;
    // }

    // Simulate packet loss (receive only repair symbols)
    std::vector<Symbol> received = encoded; // Use all repair symbols

    // Decode
    try {
        std::vector<std::vector<uint8_t>> decoded = decode_raptor(received, num_source, symbol_size);

        // Print results
        std::cout << "Original packets (first 5):\n";
        // for (size_t i = 0; i < std::min<size_t>(5, packets.size()); ++i) {
        //     for (uint8_t b : packets[i]) std::cout << (int)b << " ";
        //     std::cout << "\n";
        // }
        std::cout << "Decoded packets (first 5):\n";
        // for (size_t i = 0; i < std::min<size_t>(5, decoded.size()); ++i) {
        //     for (uint8_t b : decoded[i]) std::cout << (int)b << " ";
        //     std::cout << "\n";
        // }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }

    return 0;
}