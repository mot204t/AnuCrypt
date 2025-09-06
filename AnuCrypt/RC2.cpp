#include "RC2.h"
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

std::string RC2Hash::hash(const std::vector<uint8_t>& data) {
    try {
        CryptoPP::byte digest[CryptoPP::SHA1::DIGESTSIZE];
        CryptoPP::SHA1().CalculateDigest(digest, data.data(), data.size());

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