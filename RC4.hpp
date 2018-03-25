
#ifndef RC4_RC4_HPP
#define RC4_RC4_HPP

class RC4_cipher {
    //Массив перестановок байт: x -> S[x]:
    unsigned char S[256];
    //Ключ с возможной длиной от 1 до 256 байт:
    unsigned char *key = nullptr;
    unsigned short keyLength = 0;
    //Счетчики:
    unsigned char Q1, Q2;
    //Инициализация начального состояния с помощью текущего ключа:
    bool init();
    //Изменение состояния и выработка очередного значения гаммы:
    unsigned char change_state();
public:
    //Установка нового ключа:
    bool setKey(const unsigned char *key, unsigned short keyLength);
    //Шифрование/расшифрование текста. Флаг encrypting различия шифрования и расшифрования необходим,
    //так как шифртекст записывается (считывается) в виде кодов символов, а не самих символов.
    //Такой подход позволяет просматривать файл с шифртекстом без появления нечитаемых символов
    bool encryptDecrypt(const char *inFileName, const char *outFileName, bool encrypting);
    ~RC4_cipher();
};

#endif //RC4_RC4_HPP
