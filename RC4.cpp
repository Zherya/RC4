#include <iostream>
#include <fstream>
#include <stdexcept>
#include "RC4.hpp"

//
// Created by Дмитрий Жерегеля on 22.03.2018.
//

bool RC4_cipher::init() {
    if (key == nullptr)
        return false;
    //RC4 KSA (key-scheduling) - алгоритм (алгоритм инициализации):
    for (unsigned short i = 0; i < 256; ++i) {
        S[i] = static_cast<unsigned char>(i);
    }
    //Здесь и далее все операции по модулю 2^8 = 256 выполняются "автоматически" за счет переполнения
    //типа unsigned char, размер которого равен 1 байт = 8 бит,
    //и, следовательно, количество значений которого равно 2^8 = 256.
    unsigned char q = 0;
    for (unsigned short i = 0; i < 256; ++i) {
        q += S[i] + key[ i % keyLength ];
        //Обмен значений S[i] и S[q]:
        S[i] ^= S[q]; //S[i] = S[i]^S[q]
        S[q] ^= S[i]; //S[q] = S[q]^S[i]^S[q] = S[i]
        S[i] ^= S[q]; //S[i] = S[i]^S[q]^S[i] = S[q]
    }
    Q1 = Q2 = 0;
    return true;
}

unsigned char RC4_cipher::change_state() {
    //RC4 PRGA (pseudo-random generation algorithm) - алгоритм (алгоритм выработки гаммы):
    ++Q1;
    Q2 += S[Q1];
    //Обмен значений S[Q1] и S[Q2]:
    S[Q1] ^= S[Q2];
    S[Q2] ^= S[Q1];
    S[Q1] ^= S[Q2];
    //В данном месте необходимо явное взятие выражения по модулю, так как результат
    //сложения без записи значения в объект типа char не приводится по модулю:
    return S[ (S[Q1] + S[Q2]) % 256 ];
}

bool RC4_cipher::setKey(const unsigned char *newKey, const unsigned short newKeyLength) {
    if (newKeyLength == 0 || newKeyLength > 256) {
        std::cout << "Длина ключа не может быть равна нулю или быть больше 2048 бит = 256 байт "
                  << "(не все значения ключей будут использованы)\n";
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

bool RC4_cipher::encryptDecrypt(const char *inFileName, const char *outFileName, const bool encypting)  {
    std::ifstream in(inFileName);
    std::ofstream out(outFileName);
    if (!in || !out) {
        std::cout << "Ошибка открытия по крайней мере одного из файлов\n";
        return false;
    }
    std::string inStr;
    if (!init()) {
        std::cout << "Ключ не установлен\n";
        return false;
    }
    unsigned char gamma, c;
    while (!in.eof()) {
        //Входной текст (открытый текст или шифртекст) читается построчно:
        std::getline(in, inStr);
        if (!in) {
            //getline() выставляет fail bit в случае, если считалось 0 символов
            //или произошла ошибка чтения. Если считалось 0 символов, то это означает конец файла.
            //В таком случае переходим к следующей итерации и проверяем eof():
            if (inStr.length() == 0)
                continue;
            else {
                //Иначе возникла действительная ошибка чтения:
                std::cout << "Возникла ошибка при чтении из файла\n";
                return false;
            }
        }
        //Если активен режим шифрования, то входной файл содержит просто символы,
        //а шифртекст записывается в виде шестнадцетиричных кодов через пробелы,
        //чтобы коды можно было удобно в символы преобразовать в дальнейшем при расшифровании:
        if (encypting)
            for (char s: inStr) {
                gamma = change_state();
                c = s ^ gamma;
                out << std::hex << static_cast<short>(c) << std::dec << ' ';
                if (!out) {
                    std::cout << "Возникла ошибка при записи в файл\n";
                    return false;
                }
            }
        else {
            //В случае расшифрования - наоборот - считываются коды символов,
            //а записываются просто символы:
            std::size_t pos;
            for ( ; ; ) {
                try {
                    //Преобразует символы строки в число:
                    //(pos - индекс элемента, следующего за последним преобразованным,
                    //следовательно, он же - число преобразованных символов)
                    c = std::stoi(inStr, &pos, 16);
                    //В случае, если в строке не оказалось больше кодов символов для преобразования
                    //в числа, stoi() бросает соответствующее исключение, которое обрабатывается, и
                    //цикл завершается:
                } catch (const std::invalid_argument&) {
                    break;
                }
                //Удаляет преобразованные элементы в диапазоне [0, pos):
                inStr.erase(0, pos);
                gamma = change_state();
                c ^= gamma;
                out << c;
                if (!out) {
                    std::cout << "Возникла ошибка при записи в файл\n";
                    return false;
                }
            }
        }
        //Как сказано выше, информация из файла читается по строкам,
        //и функция getline() считывает из файла символ перевода строки, однако
        //не добавляет его в std::string, поэтому нужно либо вручную добавить символ
        //перевода строки в std::string, чтобы шифровать открытый текст вместе со всеми системными
        //символами, либо пропустить его, но каким-либо другим образом указать его наличие
        //в данном месте в открытом тексте. В данной программе выбран такой способ, в котором
        //символ перевода строки не шифруется, а вставляется в шифртексте на анологичном открытому
        //тексту месте в исходном виде. Поэтому, что при шифровании, что и при расшифровании после преобразования
        //очередной строки входного файла в выходной файл добавляется символ перевода строки:
        out << '\n';
    }
    in.close();
    out.close();
    return true;
}

RC4_cipher::~RC4_cipher() {
    delete [] key;
}
