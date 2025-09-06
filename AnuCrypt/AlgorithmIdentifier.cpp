#include "AlgorithmIdentifier.h"
#include <fstream>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <algorithm>
#include <cctype>

AlgorithmIdentifier::AlgorithmType AlgorithmIdentifier::identifyFromFile(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        return UNKNOWN;
    }

    // Try to read first byte to identify encrypted files
    uint8_t algId;
    if (file.read(reinterpret_cast<char*>(&algId), sizeof(algId))) {
        file.close();

        switch (algId) {
        case 0x01:
            return AES128;
        case 0x02:
            return AES256;
        default:
            break;
        }
    }
    else {
        file.close();
    }

    // If not an encrypted file, read content to check for hashes or Base64
    file.open(filepath, std::ios::binary);
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    if (size > 0) {
        file.seekg(0, std::ios::beg);
        std::string content(size, '\0');
        file.read(&content[0], size);
        file.close();

        // Remove whitespace and newlines
        content.erase(std::remove_if(content.begin(), content.end(), ::isspace), content.end());

        // Check if content looks like hexadecimal hash
        if (content.find_first_not_of("0123456789ABCDEFabcdef") == std::string::npos) {
            return identifyHashFromHex(content);
        }

        // Check if content looks like Base64
        if (content.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") == std::string::npos) {
            return BASE64_ENCODED;
        }
    }
    else {
        file.close();
    }

    return UNKNOWN;
}

AlgorithmIdentifier::AlgorithmType AlgorithmIdentifier::identifyFromText(const std::string& text) {
    if (text.empty()) {
        return UNKNOWN;
    }

    // Remove whitespace and newlines
    std::string cleanText = text;
    cleanText.erase(std::remove_if(cleanText.begin(), cleanText.end(), ::isspace), cleanText.end());

    // Check if text looks like hexadecimal hash
    if (cleanText.find_first_not_of("0123456789ABCDEFabcdef") == std::string::npos) {
        return identifyHashFromHex(cleanText);
    }

    // Check if text looks like Base64 encoded data
    if (cleanText.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") == std::string::npos) {
        // Additional validation - try to decode it
        try {
            CryptoPP::Base64Decoder decoder;
            decoder.Put(reinterpret_cast<const CryptoPP::byte*>(cleanText.data()), cleanText.size());
            decoder.MessageEnd();

            if (decoder.MaxRetrievable() > 0) {
                return BASE64_ENCODED;
            }
        }
        catch (...) {
            // If decoding fails, it's probably not Base64
        }
    }

    return UNKNOWN;
}

AlgorithmIdentifier::AlgorithmType AlgorithmIdentifier::identifyHashFromHex(const std::string& hexString) {
    size_t length = hexString.length();

    switch (length) {
    case 32:  // 128 bits
        return MD5_HASH;
    case 40:  // 160 bits
        return SHA1_HASH;
    case 64:  // 256 bits
        return SHA256_HASH;
    default:
        return UNKNOWN;
    }
}

std::string AlgorithmIdentifier::algorithmToString(AlgorithmType alg) {
    switch (alg) {
    case AES128:
        return "AES-128";
    case AES256:
        return "AES-256";
    case BASE64_ENCODED:
        return "Base64 Encoded";
    case MD5_HASH:
        return "MD5 Hash";
    case SHA1_HASH:
        return "SHA-1 Hash";
    case SHA256_HASH:
        return "SHA-256 Hash";
    default:
        return "Unknown";
    }
}