#pragma once
#include <string>

class AlgorithmIdentifier {
public:
    enum AlgorithmType {
        AES128,
        AES256,
        BASE64_ENCODED,
        MD5_HASH,
        SHA1_HASH,
        SHA256_HASH,
        UNKNOWN
    };

    static AlgorithmType identifyFromFile(const std::string& filepath);
    static AlgorithmIdentifier::AlgorithmType identifyFromText(const std::string& text);
    static std::string algorithmToString(AlgorithmType alg);

private:
    static AlgorithmType identifyHashFromHex(const std::string& hexString);
};