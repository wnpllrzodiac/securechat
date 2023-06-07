#include <openssl/aes.h>
#include <iostream>
#include <string>
#include <cstring>


void encrypt_AES(char* plaintext, size_t length)
{
    // Ключ для шифрования
    const unsigned char key[] = "0123456789abcdef";

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
    const unsigned char key[] = "0123456789abcdef";

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
