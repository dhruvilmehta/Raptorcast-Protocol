#include "BlockLoader.h"
#include "Chunker.h"
#include "MerkleTreeBuilder.h"
#include "PacketBuilder.h"
#include <iostream>
#include <iomanip>
#include <chrono>
#include "ChunkHeaderBuilder.h"
#include "HeaderBuilder.h"
#include "UdpSender.h"
#include "ProcessManager.h"

int main() {
    ProcessManager::processBlock("block.txt");
    return 0;
}
