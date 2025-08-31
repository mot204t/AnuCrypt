#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <map>
#include <windows.h>

// Force C++17 filesystem - suppress deprecation warning
#define _SILENCE_EXPERIMENTAL_FILESYSTEM_DEPRECATION_WARNING
#if defined(_MSC_VER) && (_MSC_VER >= 1910)  // VS 2017 and later
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#endif

#include "KeyGenerator.h"
#include "KeyValidator.h"
#include "AES128Encryptor.h"
#include "AES128Decryptor.h"
#include "AES256Encryptor.h"
#include "AES256Decryptor.h"
#include "FileValidator.h"

// Global settings
std::string defaultKeyPath = "";

// Load settings.ini
void loadSettings() {
    std::ifstream file("settings.ini");
    std::string line;
    while (std::getline(file, line)) {
        if (line.find("default_key=") != std::string::npos) {
            defaultKeyPath = line.substr(12);
        }
    }
    file.close();
}

// Save settings.ini
void saveSettings() {
    std::ofstream file("settings.ini");
    file << "default_key=" << defaultKeyPath << std::endl;
    file.close();
}

// Compatible relative path function
std::string getRelativePath(const fs::path& fullPath, const fs::path& baseDir) {
    std::string fullPathStr = fullPath.string();
    std::string baseDirStr = baseDir.string();

    // Ensure baseDir ends with separator
    if (!baseDirStr.empty() && baseDirStr.back() != '\\' && baseDirStr.back() != '/') {
        baseDirStr += '\\';
    }

    // Remove base directory from full path
    if (fullPathStr.substr(0, baseDirStr.length()) == baseDirStr) {
        return fullPathStr.substr(baseDirStr.length());
    }

    return fullPathStr;
}

// Generate default output path for a file - NEW CORRECT NAMING
std::string generateDefaultOutputPath(const std::string& inputPath, bool isEncrypting) {
    if (isEncrypting) {
        // For encryption: <filename>.<extension>.crypt
        return inputPath + ".crypt";
    }
    else {
        // For decryption: remove .crypt extension
        size_t cryptPos = inputPath.rfind(".crypt");
        if (cryptPos != std::string::npos) {
            return inputPath.substr(0, cryptPos);
        }
        else {
            return inputPath + ".decrypted";
        }
    }
}

// Print help
void printHelp() {
    std::cout << "AnuCrypt - AES Encryption Tool\n";
    std::cout << "Commands:\n";
    std::cout << "  -gk <bits>           : Generate key (128, 192, 256)\n";
    std::cout << "  -e / --encrypt       : Encrypt file or folder\n";
    std::cout << "  -d / --decrypt       : Decrypt file\n";
    std::cout << "  -f / --folder        : Encrypt all files in folder (recursive)\n";
    std::cout << "  -vk / --validatekey  : Validate key file\n";
    std::cout << "  -dk / --defaultkey   : Set default key path\n";
    std::cout << "  -h / --help          : Show this help\n";
    std::cout << "\nUsage:\n";
    std::cout << "  anucrypt.exe -gk 256\n";
    std::cout << "  anucrypt.exe -e -aes128 file.txt file.txt.crypt key.crypt.key\n";
    std::cout << "  anucrypt.exe -e -aes256 file.txt key.crypt.key\n";
    std::cout << "  anucrypt.exe -e -aes256 -f ./input ./output key.crypt.key\n";
    std::cout << "  anucrypt.exe -d -aes128 file.txt.crypt file.txt key.crypt.key\n";
    std::cout << "  anucrypt.exe -d -aes256 file.txt.crypt key.crypt.key\n";
    std::cout << "  anucrypt.exe -vk key.crypt.key\n";
    std::cout << "  anucrypt.exe -dk key.crypt.key\n";
}

int main(int argc, char* argv[]) {
    loadSettings();

    if (argc < 2) {
        printHelp();
        return 1;
    }

    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        args.push_back(argv[i]);
    }

    std::string cmd = args[0];

    // Shortcuts
    std::map<std::string, std::string> aliases = {
        {"-e", "--encrypt"},
        {"-d", "--decrypt"},
        {"-f", "--folder"},
        {"-gk", "--genkey"},
        {"-vk", "--validatekey"},
        {"-dk", "--defaultkey"},
        {"-h", "--help"}
    };

    if (aliases.find(cmd) != aliases.end()) {
        cmd = aliases[cmd];
    }

    if (cmd == "--help" || cmd == "-h") {
        printHelp();
        return 0;
    }

    if (cmd == "--genkey" || cmd == "-gk") {
        if (args.size() < 2) {
            std::cerr << "Usage: --genkey <128|192|256>\n";
            return 1;
        }
        int bits = std::stoi(args[1]);
        if (bits != 128 && bits != 192 && bits != 256) {
            std::cerr << "Invalid key size. Use 128, 192, or 256.\n";
            return 1;
        }
        std::vector<uint8_t> key = KeyGenerator::generateRandomKey(bits);
        std::string filename = "key_" + std::to_string(bits) + ".crypt.key";
        if (KeyGenerator::saveKey(key, filename)) {
            std::cout << "Key generated: " << filename << std::endl;
        }
        else {
            std::cerr << "Failed to save key.\n";
        }
        return 0;
    }

    if (cmd == "--validatekey" || cmd == "-vk") {
        if (args.size() < 2) {
            std::cerr << "Usage: --validatekey <keyfile>\n";
            return 1;
        }
        if (KeyValidator::validateKey(args[1])) {
            std::cout << "Key is valid.\n";
        }
        else {
            std::cerr << "Invalid key.\n";
        }
        return 0;
    }

    if (cmd == "--defaultkey" || cmd == "-dk") {
        if (args.size() < 2) {
            std::cerr << "Usage: --defaultkey <keypath>\n";
            return 1;
        }
        defaultKeyPath = args[1];
        saveSettings();
        std::cout << "Default key set to: " << defaultKeyPath << std::endl;
        return 0;
    }

    if (cmd == "--encrypt" || cmd == "-e") {
        if (args.size() < 4) {
            std::cerr << "Usage: --encrypt -aes128|-aes256 <input> <output> <key>\n";
            std::cerr << "Or: --encrypt -aes128|-aes256 <input> <key>\n";
            std::cerr << "Or: --encrypt -f <input_folder> <output_folder> <key>\n";
            return 1;
        }

        bool isFolder = false;
        bool is128 = false;
        bool is256 = false;
        int argOffset = 1;

        if (args[1] == "-f" || args[1] == "--folder") {
            isFolder = true;
            if (args.size() < 5) {
                std::cerr << "Usage: --encrypt -f <input_folder> <output_folder> <key>\n";
                return 1;
            }
            argOffset = 2;
        }
        else if (args[1] == "-aes128") {
            is128 = true;
        }
        else if (args[1] == "-aes256") {
            is256 = true;
        }
        else {
            std::cerr << "Invalid encryption mode. Use -aes128 or -aes256.\n";
            return 1;
        }

        if (isFolder) {
            std::string inputDir = args[2];
            std::string outputDir = args[3];
            std::string keyPath = args[4];

            std::vector<uint8_t> key;
            if (!KeyGenerator::loadKey(keyPath, key)) {
                std::cerr << "Error loading key.\n";
                return 1;
            }

            if (!fs::exists(inputDir)) {
                std::cerr << "Input folder does not exist.\n";
                return 1;
            }

            fs::create_directories(outputDir);

            // Fixed directory traversal - compatible with older filesystem versions
            try {
                for (auto it = fs::recursive_directory_iterator(inputDir);
                    it != fs::recursive_directory_iterator();
                    ++it) {
                    // Check if it's a regular file (compatible way)
                    if (fs::is_regular_file(it->path())) {
                        // Use compatible relative path function
                        std::string relPath = getRelativePath(it->path(), inputDir);
                        std::string outPath = (fs::path(outputDir) / relPath).string();
                        fs::create_directories(fs::path(outPath).parent_path());

                        std::string cryptName = outPath + ".crypt";

                        std::string error;
                        bool success = false;

                        if (is128) {
                            success = AES128Encryptor::encryptFile(it->path().string(), cryptName, key, error);
                        }
                        else if (is256) {
                            success = AES256Encryptor::encryptFile(it->path().string(), cryptName, key, error);
                        }
                        else {
                            std::cerr << "Invalid encryption mode for folder operation.\n";
                            return 1;
                        }

                        if (!success) {
                            std::cerr << "Error encrypting " << it->path() << ": " << error << std::endl;
                        }
                        else {
                            std::cout << "Encrypted: " << it->path() << " -> " << cryptName << std::endl;
                        }
                    }
                }
            }
            catch (const std::exception& e) {
                std::cerr << "Error traversing directory: " << e.what() << std::endl;
                return 1;
            }
            return 0;
        }

        // Single file encryption
        std::string inputPath = args[argOffset + 1];
        std::string keyPath = args[argOffset + 2];
        std::string outputPath;

        // Check if output path is provided
        if (args.size() > (argOffset + 3)) {
            outputPath = args[argOffset + 3];
        }
        else {
            // Generate default output path in the same directory as input with correct naming
            outputPath = generateDefaultOutputPath(inputPath, true); // true = encrypting
        }

        std::vector<uint8_t> key;
        if (!KeyGenerator::loadKey(keyPath, key)) {
            std::cerr << "Error loading key.\n";
            return 1;
        }

        std::string error;
        bool success;
        if (is128) {
            success = AES128Encryptor::encryptFile(inputPath, outputPath, key, error);
        }
        else if (is256) {
            success = AES256Encryptor::encryptFile(inputPath, outputPath, key, error);
        }
        else {
            std::cerr << "Invalid encryption mode.\n";
            return 1;
        }

        if (success) {
            std::cout << "Encrypted: " << outputPath << std::endl;
        }
        else {
            std::cerr << "Encryption failed: " << error << std::endl;
        }
        return 0;
    }

    if (cmd == "--decrypt" || cmd == "-d") {
        if (args.size() < 4) {
            std::cerr << "Usage: --decrypt -aes128|-aes256 <input> <output> <key>\n";
            std::cerr << "Or: --decrypt -aes128|-aes256 <input> <key>\n";
            return 1;
        }

        bool is128 = (args[1] == "-aes128");
        bool is256 = (args[1] == "-aes256");
        std::string inputPath = args[2];
        std::string keyPath = args[3];
        std::string outputPath;

        // Check if output path is provided
        if (args.size() > 4) {
            outputPath = args[4];
        }
        else {
            // Generate default output path in the same directory as input
            outputPath = generateDefaultOutputPath(inputPath, false); // false = decrypting
        }

        std::vector<uint8_t> key;
        if (!KeyGenerator::loadKey(keyPath, key)) {
            std::cerr << "Error loading key.\n";
            return 1;
        }

        std::string error;
        bool success;
        if (is128) {
            success = AES128Decryptor::decryptFile(inputPath, outputPath, key, error);
        }
        else if (is256) {
            success = AES256Decryptor::decryptFile(inputPath, outputPath, key, error);
        }
        else {
            std::cerr << "Invalid decryption mode. Use -aes128 or -aes256.\n";
            return 1;
        }

        if (success) {
            std::cout << "Decrypted: " << outputPath << std::endl;
        }
        else {
            std::cerr << "Decryption failed: " << error << std::endl;
        }
        return 0;
    }

    std::cerr << "Unknown command: " << cmd << std::endl;
    printHelp();
    return 1;
}