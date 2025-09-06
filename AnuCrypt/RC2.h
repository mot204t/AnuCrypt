#pragma once
#include <string>
#include <vector>

class RC2Hash {
public:
    static std::string hash(const std::vector<uint8_t>& data);
};