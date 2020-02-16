#include <iostream>
#include <fstream>
#include "RC4.hpp"

// Функция инициализации начального состояния с помощью текущего ключа.
// Возвращает true в случае успеха и false в случае неудачи.
bool RC4_cipher::init() {
    // Если ключ не установлен:
    if (key == nullptr)
        return false;

    // RC4 KSA (key-scheduling) - алгоритм (алгоритм инициализации):
    for (unsigned short i = 0; i < 256; ++i)
        S[i] = static_cast<unsigned char>(i);
    // Здесь и далее все операции по модулю 2^8 = 256 выполняются "автоматически" за счет переполнения
    // типа unsigned char, размер которого равен 1 байт = 8 бит,
    // и, следовательно, количество значений которого равно 2^8 = 256.
    unsigned char q = 0;
    for (unsigned short i = 0; i < 256; ++i) {
        q += S[i] + key[ i % keyLength ];
        // Обмен значений S[i] и S[q]:
        S[i] ^= S[q]; // S[i] = S[i]^S[q]
        S[q] ^= S[i]; // S[q] = S[q]^S[i]^S[q] = S[i]
        S[i] ^= S[q]; // S[i] = S[i]^S[q]^S[i] = S[q]
    }
    Q1 = Q2 = 0;
    return true;
}

// Функция изменения текущего состояния шифра и выработки очередного
// значения гаммы. Функция возвращает выработанный байт гаммы.
unsigned char RC4_cipher::changeState() {
    // RC4 PRGA (pseudo-random generation algorithm) - алгоритм (алгоритм выработки гаммы):
    ++Q1;
    Q2 += S[Q1];
    // Обмен значений S[Q1] и S[Q2]:
    S[Q1] ^= S[Q2];
    S[Q2] ^= S[Q1];
    S[Q1] ^= S[Q2];
    // В данном месте необходимо явное взятие выражения по модулю, так как результат
    // сложения без записи значения в объект типа unsigned char не приводится по модулю:
    return S[ (S[Q1] + S[Q2]) % 256 ];
}

// Функция установки нового ключа.
// Параметр key - указатель на область данных, где располагается новый ключ.
// Параметр keyLength - длина нового ключа (в байтах).
// Функция возвращает true в случае успеха и false в случае неудачи.
bool RC4_cipher::setKey(const unsigned char *newKey, const unsigned short newKeyLength) {
    if (newKeyLength == 0 || newKeyLength > 256) {
        std::cout << "Длина ключа не может быть равна нулю или быть больше 2048 бит = 256 байт "
                  << "(не весть ключ будет использован)\n";
        return false;
    }
    if (newKeyLength < 256)
        std::cout << "Не рекомендуется использовать ключ длины меньше 2048 бит = 256 байт\n";

    delete [] key;
    keyLength = newKeyLength;
    key = new unsigned char[keyLength];
    for (unsigned short i = 0; i < keyLength; ++i)
        key[i] = newKey[i];
    return true;
}

// Функция шифрования/расшифрования текстового файла с помощью текущего ключа.
// Параметр inFileName - указатель на строку с именем входного файла шифрования.
// Параметр outFileName - указатель на строку с именем выходного файла шифрования.
// Функция возвращает true в случае успеха и false в случае неудачи.
bool RC4_cipher::encryptDecrypt(const char *inFileName, const char *outFileName)  {
    std::ifstream inFile(inFileName, std::ios::binary);
    std::ofstream outFile(outFileName, std::ios::binary);
    if (!inFile || !outFile) {
        std::cout << "Ошибка открытия по крайней мере одного из файлов\n";
        return false;
    }
    if (!init()) {
        std::cout << "Ключ не установлен\n";
        return false;
    }
    unsigned char gamma;
    char inChars[256], outChar;
    // Значение, описывающее число считанных из входного файла символов:
    std::streamsize charsReaded;
    while (!inFile.eof()) {
        // Входной текст (открытый текст или шифртекст) считывается по 256 байт:
        inFile.read(inChars, 256);
        if (!inFile)
            // При достижении конца файла read() выставляет failbit | eofbit,
            // то есть и eofbit, и failbit, поэтому, если не выставлен eofbit,
            // то возникла действительная ошибка чтения:
            if (!inFile.eof()) {
                std::cout << "Возникла ошибка при чтении из файла\n";
                return false;
            }
        charsReaded = inFile.gcount();
        for (size_t i = 0; i < charsReaded; ++i) {
            gamma = changeState();
            outChar = inChars[i] ^ gamma;
            outFile << outChar;
            if (!outFile) {
                std::cout << "Возникла ошибка при записи в файл\n";
                return false;
            }
        }
    }
    std::cout << '\n' << std::dec;
    inFile.close();
    outFile.close();
    return true;
}

RC4_cipher::~RC4_cipher() {
    delete [] key;
}
