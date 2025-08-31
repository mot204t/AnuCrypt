#pragma once
#include <string>
#include <vector>

class KeyGenerator {
public:
    static std::vector<uint8_t> generateRandomKey(int bits);
    static bool saveKey(const std::vector<uint8_t>& key, const std::string& filename);
    static bool loadKey(const std::string& filename, std::vector<uint8_t>& outKey);
};