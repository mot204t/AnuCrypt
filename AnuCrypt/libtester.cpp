#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <iostream>

int main() {
    CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
    std::cout << "Crypto++ working!" << std::endl;
    return 0;
}