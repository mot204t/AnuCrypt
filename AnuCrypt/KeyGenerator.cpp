#include "KeyGenerator.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>

std::vector<uint8_t> KeyGenerator::generateRandomKey(int bits) {
    auto rng = new CryptoPP::AutoSeededRandomPool;
    std::vector<uint8_t> key(bits / 8);
    rng->GenerateBlock(key.data(), key.size());
    delete rng;
    return key;
}

bool KeyGenerator::saveKey(const std::vector<uint8_t>& key, const std::string& filename) {
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) return false;
    file.write(reinterpret_cast<const char*>(key.data()), key.size());
    file.close();
    return true;
}

bool KeyGenerator::loadKey(const std::string& filename, std::vector<uint8_t>& outKey) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) return false;
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    outKey.resize(size);
    file.read(reinterpret_cast<char*>(outKey.data()), size);
    file.close();
    return true;
}