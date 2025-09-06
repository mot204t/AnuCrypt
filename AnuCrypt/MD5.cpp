#include "MD5.h"
#include <cryptopp/md5.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

std::string MD5::hash(const std::vector<uint8_t>& data) {
    try {
        CryptoPP::byte digest[CryptoPP::MD5::DIGESTSIZE];
        CryptoPP::MD5().CalculateDigest(digest, data.data(), data.size());

        std::string output;
        CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(output));
        encoder.Put(digest, sizeof(digest));
        encoder.MessageEnd();

        return output;
    }
    catch (...) {
        return "";
    }
}