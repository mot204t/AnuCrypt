#pragma once
#include <string>
#include <vector>

class AES256Decryptor {
public:
    static bool decryptFile(const std::string& inputPath, const std::string& outputPath,
                            const std::vector<uint8_t>& key, std::string& error);
    
private:
    static void readHeader(std::ifstream& in, std::vector<uint8_t>& iv, std::string& md5);
};