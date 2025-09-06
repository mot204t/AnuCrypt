#include "Base64Decoder.h"
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>

std::vector<uint8_t> Base64Decoder::decode(const std::string& encoded) {
    std::vector<uint8_t> decoded;
    CryptoPP::Base64Decoder decoder;
    decoder.Put(reinterpret_cast<const CryptoPP::byte*>(encoded.data()), encoded.size());
    decoder.MessageEnd();

    CryptoPP::word64 size = decoder.MaxRetrievable();
    if (size) {
        decoded.resize(size);
        decoder.Get(reinterpret_cast<CryptoPP::byte*>(decoded.data()), decoded.size());
    }

    return decoded;
}