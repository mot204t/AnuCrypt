#pragma once
#include <string>
#include <vector>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>

class Base64Decoder {
public:
    static std::vector<uint8_t> decode(const std::string& encoded);
};