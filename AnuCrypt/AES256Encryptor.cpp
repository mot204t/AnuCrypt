#include "AES256Encryptor.h"
#include "FileValidator.h"
#include "KeyGenerator.h"
#include <fstream>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h> 

bool AES256Encryptor::encryptFile(const std::string& inputPath, const std::string& outputPath,
    const std::vector<uint8_t>& key, std::string& error) {
    try {
        std::string md5 = FileValidator::computeMD5(inputPath);

        CryptoPP::AutoSeededRandomPool rng;
        std::vector<uint8_t> iv(12);
        rng.GenerateBlock(iv.data(), iv.size());

        std::string ciphertext;
        CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

        CryptoPP::FileSource fs(inputPath.c_str(), true,
            new CryptoPP::AuthenticatedEncryptionFilter(enc,
                new CryptoPP::StringSink(ciphertext)
            )
        );

        std::ofstream outFile(outputPath, std::ios::binary);
        if (!outFile.is_open()) {
            error = "Cannot open output file.";
            return false;
        }

        uint8_t algId = 0x02; 
        outFile.write(reinterpret_cast<const char*>(&algId), sizeof(algId));
        outFile.write(reinterpret_cast<const char*>(iv.data()), iv.size());
        outFile.write(md5.data(), md5.size());
        outFile.write(ciphertext.data(), ciphertext.size());
        outFile.close();

        return true;
    }
    catch (const std::exception& e) {
        error = e.what();
        return false;
    }
}