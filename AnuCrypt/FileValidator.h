#pragma once
#include <string>

class FileValidator {
public:
    static std::string computeMD5(const std::string& filename);
    static bool verifyMD5(const std::string& filename, const std::string& expectedHash);
};