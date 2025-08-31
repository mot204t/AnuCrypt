#include "KeyValidator.h"
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>

bool KeyValidator::validateKey(const std::string& keyPath) {
    std::vector<uint8_t> key;
    if (!KeyGenerator::loadKey(keyPath, key)) return false;
    return isKeyValidSize(key, 128) || isKeyValidSize(key, 192) || isKeyValidSize(key, 256);
}

bool KeyValidator::isKeyValidSize(const std::vector<uint8_t>& key, int expectedBits) {
    return key.size() == (expectedBits / 8);
}