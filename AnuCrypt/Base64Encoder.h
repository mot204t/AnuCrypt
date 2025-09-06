#pragma once
#include <string>
#include <vector>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>

class Base64Encoder {
public:
    static std::string encode(const std::vector<uint8_t>& data);
};