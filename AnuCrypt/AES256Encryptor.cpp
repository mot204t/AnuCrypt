#include "AES256Encryptor.h"
#include "FileValidator.h"
#include "KeyGenerator.h"
#include <fstream>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>  // Add this missing include

bool AES256Encryptor::encryptFile(const std::string& inputPath, const std::string& outputPath,
    const std::vector<uint8_t>& key, std::string& error) {
    try {
        // Compute MD5 of original file
        std::string md5 = FileValidator::computeMD5(inputPath);

        // Generate 96-bit IV
        CryptoPP::AutoSeededRandomPool rng;
        std::vector<uint8_t> iv(12);
        rng.GenerateBlock(iv.data(), iv.size());

        // Encrypt using AES-256-GCM
        std::string ciphertext;
        CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

        // Use FileSource correctly with the files.h header
        CryptoPP::FileSource fs(inputPath.c_str(), true,
            new CryptoPP::AuthenticatedEncryptionFilter(enc,
                new CryptoPP::StringSink(ciphertext)
            )
        );

        // Write header: ALG_ID + IV + MD5 + Ciphertext
        // ALG_ID for AES-256 = 0x02
        std::ofstream outFile(outputPath, std::ios::binary);
        if (!outFile.is_open()) {
            error = "Cannot open output file.";
            return false;
        }

        uint8_t algId = 0x02; // AES-256
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