#include <iostream>
#include <unistd.h>
#include "RC4.hpp"

int main() {
    chdir("/Users/dmitry/Desktop");
    unsigned short keyLength = 3;
    unsigned char keys[] = "Key";
    RC4_cipher RC4;
    std::cout << "Ключ:\n" << '\"' << keys << "\"\n";
    for(char k: keys)
        std::cout << std::hex << static_cast<int>(k) << std::dec;
    std::cout << "\n\n";

    unsigned char p[] = "Attack at dawn";
    std::cout << "Текст:\n" << '\"' << p << "\"\n";
    for(char k: p)
        std::cout << std::hex << static_cast<int>(k) << std::dec;
    std::cout << "\n\n";
    RC4.setKey(keys, keyLength);
    RC4.encryptDecrypt("in.txt", "enc.txt", true);
    RC4.encryptDecrypt("enc.txt", "dec.txt", false);
    return 0;
}