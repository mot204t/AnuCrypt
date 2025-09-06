#pragma once
#include <string>
#include <vector>

class Hashing {
public:
    enum Algorithm {
        RC2_ALG,
        MD5_ALG,
        SHA256_ALG
    };

    static std::string hashData(const std::vector<uint8_t>& data, Algorithm alg);
    static std::string hashFile(const std::string& filepath, Algorithm alg);
    static std::string hashText(const std::string& text, Algorithm alg);
};