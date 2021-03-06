
#ifndef RC4_RC4_HPP
#define RC4_RC4_HPP

// Класс, содержащий внутренние параметры шифра RC4 (ключ, счетчики и т.д.)
// и методы для работы с шифром:
class RC4_cipher {
    // Массив перестановок байт: x -> S[x]:
    unsigned char S[256] = {};

    // Ключ с возможной длиной от 1 до 256 байт:
    unsigned char *key = nullptr;
    unsigned short keyLength = 0;

    // Счетчики:
    unsigned char Q1 = 0, Q2 = 0;

    // Функция инициализации начального состояния с помощью текущего ключа.
    // Возвращает true в случае успеха и false в случае неудачи.
    bool init();

    // Функция изменения текущего состояния шифра и выработки очередного
    // значения гаммы. Функция возвращает выработанный байт гаммы.
    unsigned char changeState();

public:
    // Функция установки нового ключа.
    // Параметр key - указатель на область данных, где располагается новый ключ.
    // Параметр keyLength - длина нового ключа (в байтах).
    // Функция возвращает true в случае успеха и false в случае неудачи.
    bool setKey(const unsigned char *key, unsigned short keyLength);

    // Функция шифрования/расшифрования текстового файла с помощью текущего ключа.
    // Параметр inFileName - указатель на строку с именем входного файла шифрования.
    // Параметр outFileName - указатель на строку с именем выходного файла шифрования.
    // Функция возвращает true в случае успеха и false в случае неудачи.
    bool encryptDecrypt(const char *inFileName, const char *outFileName);

    ~RC4_cipher();
};

#endif //RC4_RC4_HPP
