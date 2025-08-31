#pragma once
#include <string>
#include <vector>
#include "KeyGenerator.h"

class KeyValidator {
public:
    static bool validateKey(const std::string& keyPath);
    static bool isKeyValidSize(const std::vector<uint8_t>& key, int expectedBits);
};