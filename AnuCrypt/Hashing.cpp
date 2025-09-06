#include "Hashing.h"
#include "RC2.h"
#include "MD5.h"
#include "Sha256.h"
#include <fstream>

std::string Hashing::hashData(const std::vector<uint8_t>& data, Algorithm alg) {
    switch (alg) {
    case RC2_ALG:
        return RC2Hash::hash(data);
    case MD5_ALG:
        return MD5::hash(data);
    case SHA256_ALG:
        return Sha256::hash(data);
    default:
        return "";
    }
}

std::string Hashing::hashFile(const std::string& filepath, Algorithm alg) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        return "";
    }

    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> data(size);
    file.read(reinterpret_cast<char*>(data.data()), size);
    file.close();

    return hashData(data, alg);
}

std::string Hashing::hashText(const std::string& text, Algorithm alg) {
    std::vector<uint8_t> data(text.begin(), text.end());
    return hashData(data, alg);
}