#include "Base64Encoder.h"
#include "Base64Encoder.h"
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>

std::string Base64Encoder::encode(const std::vector<uint8_t>& data) {
    std::string encoded;
    CryptoPP::Base64Encoder encoder;
    encoder.Put(data.data(), data.size());
    encoder.MessageEnd();

    CryptoPP::word64 size = encoder.MaxRetrievable();
    if (size) {
        encoded.resize(size);
        encoder.Get(reinterpret_cast<CryptoPP::byte*>(&encoded[0]), encoded.size());
    }

    if (!encoded.empty() && encoded.back() == '\n') {
        encoded.pop_back();
    }
    if (!encoded.empty() && encoded.back() == '\r') {
        encoded.pop_back();
    }

    return encoded;
}