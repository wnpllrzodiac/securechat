#include <openssl/aes.h>
#include <iostream>
#include <string>
#include <cstring>
#include <fstream>

/**
 * @brief Function for getting the key
 * The function opens the file key.txt and gets the key
 * @return {const unsigned*} defaultKey 16 bit key 
 */
const unsigned char* getkey() {
    std::ifstream file("key.txt");
    std::string line; 

    if (file.is_open()) { 
        if (std::getline(file, line)) { 
            static const unsigned char key[] = { line.c_str()[0], line.c_str()[1], line.c_str()[2], '\0' };

            return key;
        } else {
            std::cout << "The file is empty" << std::endl;
        }
        file.close();
    } else {
        std::cout << "Сould not open the file" << std::endl;
    }

    static const unsigned char defaultKey[] = { '\0' };
    return defaultKey;
}

/**
 * @brief Encryption function
 * Encrypts text using aes-128
 * @param {char*} plaintext text for encryption
 * @param {size_t} length text length
 */
void encrypt_AES(char* plaintext, size_t length)
{
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

/**
 * @brief Decryption function
 * Decrypts text using aes-128
 * @param {char*} plaintext text for decryption
 * @param {size_t} length text length
 */
void decrypt_AES(char* ciphertext, size_t length)
{
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


