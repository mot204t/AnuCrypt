#pragma once
#include <string>
#include <vector>

class MD5 {
public:
    static std::string hash(const std::vector<uint8_t>& data);
};