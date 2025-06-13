#include <iostream>
#include "Validator.h"

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <address> <port> <stake>\n";
        return 1;
    }
    std::string address = argv[1];
    uint16_t port = static_cast<uint16_t>(atoi(argv[2]));
    double stake = atof(argv[3]);

    std::cout<<address<<std::endl;
    std::cout<<port<<std::endl;
    std::cout<<stake<<std::endl;

    Validator validator(address, port, stake);
    std::cout << "Starting Validator at " << address << ":" << port << " with stake " << stake << "\n";
    validator.run();
    return 0;
}