#include "FileValidator.h"
#include <fstream>
#include <cryptopp/md5.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>

std::string FileValidator::computeMD5(const std::string& filename) {
    try {
        CryptoPP::MD5 md5;
        std::string hash;
        
        CryptoPP::FileSource fs(filename.c_str(), true,
            new CryptoPP::HashFilter(md5,
                new CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(hash)
                )
            )
        );
        
        return hash;
    } catch (...) {
        return "";
    }
}

bool FileValidator::verifyMD5(const std::string& filename, const std::string& expectedHash) {
    std::string actualHash = computeMD5(filename);
    return actualHash == expectedHash;
}