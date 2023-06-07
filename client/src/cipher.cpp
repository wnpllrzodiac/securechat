#include <openssl/aes.h>
#include <iostream>
#include <string>
#include <cstring>
#include <fstream>


const unsigned char* getkey() {
    std::ifstream file("key.txt"); // открываем файл для чтения
    std::string line; // переменная для хранения строки

    if (file.is_open()) { // проверяем, удалось ли открыть файл
        if (std::getline(file, line)) { // считываем первую строку из файла
            
            // Преобразование строки в массив типа const unsigned char[]
            static const unsigned char key[] = { line.c_str()[0], line.c_str()[1], line.c_str()[2], '\0' };

            return key;
        } else {
            std::cout << "1" << std::endl;
        }
        file.close(); // закрываем файл
    } else {
        std::cout << "2" << std::endl;
    }

    // Если чтение файла не удалось, можно вернуть значение по умолчанию
    static const unsigned char defaultKey[] = { '\0' };
    return defaultKey;
}

void encrypt_AES(char* plaintext, size_t length)
{
    // Ключ для шифрования
    // const unsigned char key[] = "0123456789abcdef";
    const unsigned char *key = getkey();

    AES_KEY aesKey;
    AES_set_encrypt_key(key, 128, &aesKey); 

    size_t numBlocks = length / AES_BLOCK_SIZE;

    for (size_t i = 0; i < numBlocks + 1; ++i)
    {
        AES_encrypt(reinterpret_cast<const unsigned char*>(plaintext + i * AES_BLOCK_SIZE),
                    reinterpret_cast<unsigned char*>(plaintext + i * AES_BLOCK_SIZE), &aesKey);
    }
}

void decrypt_AES(char* ciphertext, size_t length)
{
    // Ключ для дешифрования
    // const unsigned char key[] = "0123456789abcdef";
    const unsigned char *key = getkey();

    AES_KEY aesKey;
    AES_set_decrypt_key(key, 128, &aesKey);

    size_t numBlocks = length / AES_BLOCK_SIZE;

    for (size_t i = 0; i < numBlocks  + 1; ++i)
    {
        AES_decrypt(reinterpret_cast<const unsigned char*>(ciphertext + i * AES_BLOCK_SIZE),
                    reinterpret_cast<unsigned char*>(ciphertext + i * AES_BLOCK_SIZE), &aesKey);
    }
}

// // Пример использования функций encrypt_AES и decrypt_AES
// int main()
// {
//     char buffer[1024] = "Thiss message se Hello my name";

//     std::cout << "Оригинальный текст: " << buffer << std::endl;

//     // Шифрование
//     encrypt_AES(buffer);
//     std::cout << "Зашифрованный текст: " << buffer << std::endl;

//     // Дешифрование
//     decrypt_AES(buffer);
//     std::cout << "Расшифрованный текст: " << buffer << std::endl;

//     return 0;
// }
