#pragma once
#include <string>
#include <vector>
#include <fstream>

class AES128Encryptor {
public:
    static bool encryptFile(const std::string& inputPath, const std::string& outputPath,
                            const std::vector<uint8_t>& key, std::string& error);
    
private:
    static void writeHeader(std::ofstream& out, const std::vector<uint8_t>& iv, const std::string& md5);
    static void readHeader(std::ifstream& in, std::vector<uint8_t>& iv, std::string& md5);
};