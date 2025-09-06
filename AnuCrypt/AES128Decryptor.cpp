#include "AES128Decryptor.h"
#include "FileValidator.h"
#include "KeyGenerator.h"
#include <fstream>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>

bool AES128Decryptor::decryptFile(const std::string& inputPath, const std::string& outputPath,
    const std::vector<uint8_t>& key, std::string& error) {
    try {
        std::ifstream inFile(inputPath, std::ios::binary);
        if (!inFile.is_open()) {
            error = "Cannot open encrypted file.";
            return false;
        }

        uint8_t algId;
        inFile.read(reinterpret_cast<char*>(&algId), sizeof(algId));

        if (algId != 0x01) {
            error = "File was not encrypted with AES-128. Use the correct decryption algorithm.";
            inFile.close();
            return false;
        }

        std::vector<uint8_t> iv(12);
        std::string storedMD5(32, '\0');
        inFile.read(reinterpret_cast<char*>(iv.data()), iv.size());
        inFile.read(&storedMD5[0], 32);

        inFile.seekg(0, std::ios::end);
        size_t totalSize = inFile.tellg();
        size_t dataStart = 1 + 12 + 32; 
        size_t dataSize = totalSize - dataStart;

        inFile.seekg(dataStart);
        std::vector<uint8_t> ciphertext(dataSize);
        inFile.read(reinterpret_cast<char*>(ciphertext.data()), dataSize);
        inFile.close();

        std::string plaintext;
        CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

        try {
            CryptoPP::StringSource ss(ciphertext.data(), ciphertext.size(), true,
                new CryptoPP::AuthenticatedDecryptionFilter(dec,
                    new CryptoPP::StringSink(plaintext)
                )
            );
        }
        catch (const CryptoPP::Exception&) {
            error = "Authentication failed - invalid key or corrupted file.";
            return false;
        }

        // Write decrypted file
        std::ofstream outFile(outputPath, std::ios::binary);
        if (!outFile.is_open()) {
            error = "Cannot create output file.";
            return false;
        }
        outFile.write(plaintext.data(), plaintext.size());
        outFile.close();

        // Verify integrity
        std::string computedMD5 = FileValidator::computeMD5(outputPath);
        if (computedMD5 != storedMD5) {
            error = "File integrity check failed - possible corruption.";
            std::remove(outputPath.c_str());
            return false;
        }

        return true;
    }
    catch (const std::exception& e) {
        error = std::string("Decryption error: ") + e.what();
        return false;
    }
}