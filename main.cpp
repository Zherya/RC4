#include <iostream>
#include <random>
#include "RC4.hpp"

//Функция randomByte() может использоваться для генерации ключей:
short randomByte() {
    //Установка генератора псевдослучайных чисел с зерном из программной энтропии:
    static std::mt19937_64 generator (std::random_device{}());
    //Распределение случайных значений в диапазоне [0,255]:
    return std::uniform_int_distribution<short>(0,255)(generator);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cout << "В области внешних аргументов должно находиться два пользовательских файла:\n"
                  << "argv[1]: Входной файл шифрования/расшифрования\n"
                  << "argv[2]: Выходной файл шифрования/расшифрования\n";
        return 0;
    }
    constexpr unsigned short keyLength = 3;
    unsigned char keys[keyLength+1] = "Key";
    RC4_cipher RC4;
    if (!RC4.setKey(keys, keyLength)) {
        std::cout << "Ошибка установки ключа\n";
        return 0;
    }

    std::cout << "Для ширования файла из внешних аргументов введите \"enc\";\n"
              << "Для расшифрования - \"dec\".\n";
    bool encrypting;
    std::string input;
    if (!(std::cin >> input)) {
        std::cout << "Ошибка ввода\n";
        return 0;
    }
    if (input == "enc")
        encrypting = true;
    else
        if (input == "dec")
            encrypting = false;
        else {
            std::cout << "Ошибочный ввод\n";
            return 0;
        }
    if (!RC4.encryptDecrypt(argv[1], argv[2], encrypting))
        std::cout << "Ошибка шифрования/расшифрования\n";
    else
        std::cout << "Работа завершена\n";

    return 0;
}