#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <map>
#include <windows.h>
#define _SILENCE_EXPERIMENTAL_FILESYSTEM_DEPRECATION_WARNING
#if defined(_MSC_VER) && (_MSC_VER >= 1910)
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
#include "Base64Encoder.h"
#include "Base64Decoder.h"
#include "Hashing.h"
#include "AlgorithmIdentifier.h"

const std::string VERSION = "1.0.0";

std::string defaultKeyPath = "";

void loadSettings() {
    if (!fs::exists("settings.ini")) {
        return;
    }

    std::ifstream file("settings.ini");
    if (!file.is_open()) {
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.find("default_key=") == 0) {
            defaultKeyPath = line.substr(12);
            if (!defaultKeyPath.empty() && defaultKeyPath.front() == '"' && defaultKeyPath.back() == '"') {
                defaultKeyPath = defaultKeyPath.substr(1, defaultKeyPath.length() - 2);
            }
            break;
        }
    }
    file.close();
}

void saveSettings() {
    std::ofstream file("settings.ini");
    if (file.is_open()) {
        file << "default_key=" << defaultKeyPath << std::endl;
        file.close();
    }
}

std::string getRelativePath(const fs::path& fullPath, const fs::path& baseDir) {
    std::string fullPathStr = fullPath.string();
    std::string baseDirStr = baseDir.string();

    if (!baseDirStr.empty() && baseDirStr.back() != '\\' && baseDirStr.back() != '/') {
        baseDirStr += '\\';
    }

    if (fullPathStr.substr(0, baseDirStr.length()) == baseDirStr) {
        return fullPathStr.substr(baseDirStr.length());
    }

    return fullPathStr;
}

std::string generateDefaultOutputPath(const std::string& inputPath, bool isEncrypting) {
    if (isEncrypting) {
        return inputPath + ".crypt";
    }
    else {
        size_t cryptPos = inputPath.rfind(".crypt");
        if (cryptPos != std::string::npos) {
            return inputPath.substr(0, cryptPos);
        }
        else {
            return inputPath + ".decrypted";
        }
    }
}

std::vector<uint8_t> readFileAsBinary(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        return std::vector<uint8_t>();
    }

    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> data(size);
    file.read(reinterpret_cast<char*>(data.data()), size);
    file.close();

    return data;
}

bool writeBinaryToFile(const std::string& filepath, const std::vector<uint8_t>& data) {
    std::ofstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    file.close();
    return true;
}

void printHelp() {
    std::cout << "AnuCrypt - A Simple File Encryptor v" << VERSION << "\n";
    std::cout << "Commands:\n";
    std::cout << "  -gk  | --generatekey  : Generate key (--128bit, --192bit, --256bit)\n";
    std::cout << "  -e   | --encrypt      : Encrypt file or folder\n";
    std::cout << "  -d   | --decrypt      : Decrypt file\n";
    std::cout << "  --encode              : Encode file or text (use with --base64)\n";
    std::cout << "  --decode              : Decode file or text (use with --base64)\n";
    std::cout << "  -f   | --folder       : Encrypt all files in folder (recursive)\n";
    std::cout << "  -vk  | --validatekey  : Validate key file\n";
    std::cout << "  -dk  | --defaultkey   : Set default key path\n";
    std::cout << "  -v   | --version      : Show version\n";
    std::cout << "  -h   | --help         : Help Information\n";
    std::cout << "  --hash                : Hash files or text\n";
    std::cout << "  -aid | --algorithmidentifier : Identify algorithm used in file\n";
    std::cout << "\nUsage:\n";
    std::cout << "  AnuCrypt --generatekey --256bit\n";
    std::cout << "  AnuCrypt --encrypt --aes256 <file> --output <output> --key <keyfile>\n";
    std::cout << "  AnuCrypt --encrypt --folder --aes256 <input_dir> --output <output_dir> --key <keyfile>\n";
    std::cout << "  AnuCrypt --decrypt --aes256 <file.crypt> --output <output> --key <keyfile>\n";
    std::cout << "  AnuCrypt --encode --base64 <file or text> [--output <file>]\n";
    std::cout << "  AnuCrypt --decode --base64 <file or text> [--output <file>]\n";
    std::cout << "  AnuCrypt --hash --rc2 <file or text> [--output <file>]\n";
    std::cout << "  AnuCrypt --hash --folder --rc2 <folder> [--output <file>]\n";
    std::cout << "  AnuCrypt --algorithmidentifier <file or text>\n";
    std::cout << "  AnuCrypt -e --base64 <file or text> [--output <file>] (short for encode)\n";
    std::cout << "  AnuCrypt -d --base64 <file or text> [--output <file>] (short for decode)\n";
}

// Parse command line arguments
std::map<std::string, std::string> parseArguments(const std::vector<std::string>& args) {
    std::map<std::string, std::string> parsedArgs;

    for (size_t i = 0; i < args.size(); ++i) {
        std::string arg = args[i];

        // Handle flags without values
        if (arg == "--128bit" || arg == "--192bit" || arg == "--256bit" ||
            arg == "--aes128" || arg == "--aes256" || arg == "--rc2" ||
            arg == "--md5" || arg == "--sha256" || arg == "--base64" ||
            arg == "--folder") {
            parsedArgs[arg] = "true";
            continue;
        }

        // Handle key-value pairs
        if (arg == "--output" || arg == "-o" ||
            arg == "--key" || arg == "-k" ||
            arg == "--algorithmidentifier" || arg == "-aid") {
            if (i + 1 < args.size()) {
                parsedArgs[arg] = args[i + 1];
                i++; // Skip next argument as it's the value
            }
            continue;
        }

        // Handle short forms
        std::map<std::string, std::string> shortForms = {
            {"-e", "--encrypt"},
            {"-d", "--decrypt"},
            {"-f", "--folder"},
            {"-gk", "--generatekey"},
            {"-vk", "--validatekey"},
            {"-dk", "--defaultkey"},
            {"-v", "--version"},
            {"-h", "--help"},
            {"-o", "--output"},
            {"-k", "--key"},
            {"-aid", "--algorithmidentifier"}
        };

        if (shortForms.find(arg) != shortForms.end()) {
            parsedArgs[shortForms[arg]] = "true";
            continue;
        }

        // Store positional arguments
        if (parsedArgs.empty() || (parsedArgs.rbegin()->first.substr(0, 2) == "--")) {
            parsedArgs[arg] = "true";
        }
        else {
            parsedArgs[arg] = "true";
        }
    }

    return parsedArgs;
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

    // Handle version command
    if (cmd == "--version" || cmd == "-v") {
        std::cout << "AnuCrypt v" << VERSION << std::endl;
        return 0;
    }

    // Handle help command
    if (cmd == "--help" || cmd == "-h") {
        printHelp();
        return 0;
    }

    // Handle algorithm identifier command
    if (cmd == "--algorithmidentifier" || cmd == "-aid") {
        if (args.size() < 2) {
            std::cerr << "Usage: --algorithmidentifier <file or text>\n";
            return 1;
        }

        std::string input = args[1];

        // First try to identify as file
        AlgorithmIdentifier::AlgorithmType alg = AlgorithmIdentifier::identifyFromFile(input);

        // If file identification fails, try as text
        if (alg == AlgorithmIdentifier::UNKNOWN) {
            alg = AlgorithmIdentifier::identifyFromText(input);
        }

        std::cout << AlgorithmIdentifier::algorithmToString(alg) << std::endl;
        return 0;
    }

    // Handle generate key command
    if (cmd == "--generatekey" || cmd == "-gk") {
        int bits = 256; // default
        for (const auto& arg : args) {
            if (arg == "--128bit") {
                bits = 128;
            }
            else if (arg == "--192bit") {
                bits = 192;
            }
            else if (arg == "--256bit") {
                bits = 256;
            }
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

    // Handle validate key command
    if (cmd == "--validatekey" || cmd == "-vk") {
        if (args.size() < 2) {
            std::cerr << "Usage: --validatekey <keyfile>\n";
            return 1;
        }

        std::string keyfile = args[1];
        if (KeyValidator::validateKey(keyfile)) {
            std::cout << "Key is valid.\n";
        }
        else {
            std::cerr << "Invalid key.\n";
        }
        return 0;
    }

    // Handle default key command
    if (cmd == "--defaultkey" || cmd == "-dk") {
        if (args.size() < 2) {
            std::cerr << "Usage: --defaultkey <keypath>\n";
            return 1;
        }

        std::string keypath = args[1];
        defaultKeyPath = keypath;
        saveSettings();
        std::cout << "Default key set to: " << defaultKeyPath << std::endl;
        return 0;
    }

    // Handle hash command
    if (cmd == "--hash") {
        Hashing::Algorithm alg = Hashing::SHA256_ALG; // default

        bool isRC2 = false, isMD5 = false, isSHA256 = false;
        bool isFolder = false;
        std::string output = "";
        std::string input = "";

        // Parse arguments
        for (size_t i = 1; i < args.size(); ++i) {
            if (args[i] == "--rc2") {
                isRC2 = true;
                alg = Hashing::RC2_ALG;
            }
            else if (args[i] == "--md5") {
                isMD5 = true;
                alg = Hashing::MD5_ALG;
            }
            else if (args[i] == "--sha256") {
                isSHA256 = true;
                alg = Hashing::SHA256_ALG;
            }
            else if (args[i] == "--folder" || args[i] == "-f") {
                isFolder = true;
            }
            else if (args[i] == "--output" || args[i] == "-o") {
                if (i + 1 < args.size()) {
                    output = args[i + 1];
                    i++;
                }
            }
            else if (input.empty() && args[i][0] != '-') {
                input = args[i];
            }
        }

        if (input.empty()) {
            std::cerr << "Usage: --hash [--rc2|--md5|--sha256] [--folder] <file or text> [--output <file>]\n";
            return 1;
        }

        // Check if folder hashing is requested
        if (isFolder) {
            if (!fs::exists(input)) {
                std::cerr << "Folder does not exist: " << input << std::endl;
                return 1;
            }

            std::ofstream outFile;
            if (!output.empty()) {
                outFile.open(output);
                if (!outFile.is_open()) {
                    std::cerr << "Cannot create output file: " << output << std::endl;
                    return 1;
                }
            }

            try {
                for (auto entry : fs::recursive_directory_iterator(input)) {
                    if (fs::is_regular_file(entry.path())) {
                        std::string hash = Hashing::hashFile(entry.path().string(), alg);
                        std::string line = entry.path().string() + ": " + hash;

                        if (outFile.is_open()) {
                            outFile << line << std::endl;
                        }
                        else {
                            std::cout << line << std::endl;
                        }
                    }
                }
            }
            catch (const std::exception& e) {
                std::cerr << "Error traversing directory: " << e.what() << std::endl;
                return 1;
            }

            if (outFile.is_open()) {
                outFile.close();
                std::cout << "Hashes written to: " << output << std::endl;
            }
        }
        else {
            // Single file or text hashing
            std::string hash;

            // Try to read as file first
            std::vector<uint8_t> fileData = readFileAsBinary(input);
            if (!fileData.empty()) {
                hash = Hashing::hashData(fileData, alg);
            }
            else {
                // Treat as text
                hash = Hashing::hashText(input, alg);
            }

            if (!output.empty()) {
                std::ofstream outFile(output);
                if (outFile.is_open()) {
                    outFile << hash << std::endl;
                    outFile.close();
                    std::cout << "Hash written to: " << output << std::endl;
                }
                else {
                    std::cerr << "Cannot create output file: " << output << std::endl;
                    return 1;
                }
            }
            else {
                std::cout << hash << std::endl;
            }
        }
        return 0;
    }

    // Handle encode command
    if (cmd == "--encode" || cmd == "-e") {
        bool isBase64 = false;
        std::string input = "";
        std::string output = "";

        // Parse arguments
        for (size_t i = 1; i < args.size(); ++i) {
            if (args[i] == "--base64") {
                isBase64 = true;
            }
            else if (args[i] == "--output" || args[i] == "-o") {
                if (i + 1 < args.size()) {
                    output = args[i + 1];
                    i++;
                }
            }
            else if (input.empty() && args[i][0] != '-') {
                input = args[i];
            }
        }

        if (isBase64 && !input.empty()) {
            // Try to read as file first
            std::vector<uint8_t> data = readFileAsBinary(input);
            if (data.empty()) {
                // If file reading failed, treat as text
                data.assign(input.begin(), input.end());
            }

            std::string encoded = Base64Encoder::encode(data);

            if (!output.empty()) {
                std::ofstream outFile(output);
                if (outFile.is_open()) {
                    outFile << encoded << std::endl;
                    outFile.close();
                    std::cout << "Encoded data written to: " << output << std::endl;
                }
                else {
                    std::cerr << "Cannot create output file: " << output << std::endl;
                    return 1;
                }
            }
            else {
                std::cout << encoded << std::endl;
            }
            return 0;
        }
    }

    // Handle decode command
    if (cmd == "--decode" || cmd == "-d") {
        bool isBase64 = false;
        std::string input = "";
        std::string output = "";

        // Parse arguments
        for (size_t i = 1; i < args.size(); ++i) {
            if (args[i] == "--base64") {
                isBase64 = true;
            }
            else if (args[i] == "--output" || args[i] == "-o") {
                if (i + 1 < args.size()) {
                    output = args[i + 1];
                    i++;
                }
            }
            else if (input.empty() && args[i][0] != '-') {
                input = args[i];
            }
        }

        if (isBase64 && !input.empty()) {
            std::string encodedData;

            // Try to read as file first
            std::vector<uint8_t> fileData = readFileAsBinary(input);
            if (!fileData.empty()) {
                encodedData.assign(fileData.begin(), fileData.end());
            }
            else {
                // If file reading failed, treat as encoded text
                encodedData = input;
            }

            std::vector<uint8_t> decoded = Base64Decoder::decode(encodedData);

            if (decoded.empty()) {
                std::cerr << "Failed to decode Base64 data.\n";
                return 1;
            }

            if (!output.empty()) {
                std::ofstream outFile(output, std::ios::binary);
                if (outFile.is_open()) {
                    outFile.write(reinterpret_cast<const char*>(decoded.data()), decoded.size());
                    outFile.close();
                    std::cout << "Decoded data written to: " << output << std::endl;
                }
                else {
                    std::cerr << "Cannot create output file: " << output << std::endl;
                    return 1;
                }
            }
            else {
                std::cout.write(reinterpret_cast<const char*>(decoded.data()), decoded.size());
                std::cout << std::endl;
            }
            return 0;
        }
    }

    // Handle encrypt command
    if (cmd == "--encrypt" || cmd == "-e") {
        bool isFolder = false;
        bool is128 = false;
        bool is256 = false;
        std::string inputPath = "";
        std::string outputPath = "";
        std::string keyPath = "";

        // Parse arguments
        for (size_t i = 1; i < args.size(); ++i) {
            if (args[i] == "--folder" || args[i] == "-f") {
                isFolder = true;
            }
            else if (args[i] == "--aes128") {
                is128 = true;
            }
            else if (args[i] == "--aes256") {
                is256 = true;
            }
            else if (args[i] == "--output" || args[i] == "-o") {
                if (i + 1 < args.size()) {
                    outputPath = args[i + 1];
                    i++;
                }
            }
            else if (args[i] == "--key" || args[i] == "-k") {
                if (i + 1 < args.size()) {
                    keyPath = args[i + 1];
                    i++;
                }
            }
            else if (inputPath.empty() && args[i][0] != '-') {
                inputPath = args[i];
            }
        }

        if (isFolder) {
            if (args.size() < 5) {
                std::cerr << "Usage: --encrypt --folder --aes256 <input_folder> --output <output_folder> --key <keyfile>\n";
                return 1;
            }

            if (keyPath.empty() && !defaultKeyPath.empty()) {
                keyPath = defaultKeyPath;
            }

            std::vector<uint8_t> key;
            if (!KeyGenerator::loadKey(keyPath, key)) {
                std::cerr << "Error loading key from: " << keyPath << std::endl;
                return 1;
            }

            if (!fs::exists(inputPath)) {
                std::cerr << "Input folder does not exist.\n";
                return 1;
            }

            fs::create_directories(outputPath);

            try {
                for (auto it = fs::recursive_directory_iterator(inputPath);
                    it != fs::recursive_directory_iterator();
                    ++it) {
                    if (fs::is_regular_file(it->path())) {
                        std::string relPath = getRelativePath(it->path(), inputPath);
                        std::string outPath = (fs::path(outputPath) / relPath).string();
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
                            std::cerr << "Invalid encryption mode for folder operation. Use --aes128 or --aes256.\n";
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
        else {
            if (inputPath.empty()) {
                std::cerr << "Usage: --encrypt --aes256 <input> [--output <output>] --key <keyfile>\n";
                return 1;
            }

            if (keyPath.empty()) {
                if (!defaultKeyPath.empty()) {
                    keyPath = defaultKeyPath;
                }
                else {
                    std::cerr << "No key provided and no default key set.\n";
                    return 1;
                }
            }

            if (outputPath.empty()) {
                outputPath = generateDefaultOutputPath(inputPath, true);
            }

            std::vector<uint8_t> key;
            if (!KeyGenerator::loadKey(keyPath, key)) {
                std::cerr << "Error loading key from: " << keyPath << std::endl;
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
                std::cerr << "Invalid encryption mode. Use --aes128 or --aes256.\n";
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
    }

    // Handle decrypt command
    if (cmd == "--decrypt" || cmd == "-d") {
        bool is128 = false;
        bool is256 = false;
        std::string inputPath = "";
        std::string outputPath = "";
        std::string keyPath = "";

        // Parse arguments
        for (size_t i = 1; i < args.size(); ++i) {
            if (args[i] == "--aes128") {
                is128 = true;
            }
            else if (args[i] == "--aes256") {
                is256 = true;
            }
            else if (args[i] == "--output" || args[i] == "-o") {
                if (i + 1 < args.size()) {
                    outputPath = args[i + 1];
                    i++;
                }
            }
            else if (args[i] == "--key" || args[i] == "-k") {
                if (i + 1 < args.size()) {
                    keyPath = args[i + 1];
                    i++;
                }
            }
            else if (inputPath.empty() && args[i][0] != '-') {
                inputPath = args[i];
            }
        }

        if (inputPath.empty()) {
            std::cerr << "Usage: --decrypt --aes256 <input> [--output <output>] --key <keyfile>\n";
            return 1;
        }

        if (keyPath.empty()) {
            if (!defaultKeyPath.empty()) {
                keyPath = defaultKeyPath;
            }
            else {
                std::cerr << "No key provided and no default key set.\n";
                return 1;
            }
        }

        if (outputPath.empty()) {
            outputPath = generateDefaultOutputPath(inputPath, false);
        }

        std::vector<uint8_t> key;
        if (!KeyGenerator::loadKey(keyPath, key)) {
            std::cerr << "Error loading key from: " << keyPath << std::endl;
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
            std::cerr << "Invalid decryption mode. Use --aes128 or --aes256.\n";
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