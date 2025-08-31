#pragma once
#include <string>
#include <vector>
#include <fstream>

class AES256Encryptor {
public:
    static bool encryptFile(const std::string& inputPath, const std::string& outputPath,
                            const std::vector<uint8_t>& key, std::string& error);
};