//#include <cstring>
//#include <fstream>
//#include <iostream>
#include <openssl/aes.h>
#include <openssl/des.h>
//#include <string>

/**
 * @brief Function for getting the key
 * The function opens the file key.txt and gets the key
 * @return {const unsigned char *} key 16 bit key
 */
const unsigned char *getkey() {
  /*std::ifstream file("key.txt");
  std::string line;
  static const unsigned char defaultKey[16] = {0};

  if (!file.is_open()) {
    std::cout << "Could not open the file" << std::endl;
    return defaultKey;
  }

  if (std::getline(file, line)) {
    static unsigned char key[16];
    strncpy(reinterpret_cast<char *>(key), line.c_str(), sizeof(key));
    file.close();
    return key;
  }

  std::cout << "The file is empty" << std::endl;
  file.close();
  return defaultKey;*/
    return "1234567890abcdef";
}

/**
 * @brief Encryption function
 * Encrypts text using AES-128
 * @param {char*} plaintext text for encryption
 * @param {size_t} length text length
 */
void encrypt_AES(char *plaintext, size_t length) {
  const unsigned char *key = getkey();
  AES_KEY aesKey;
  AES_set_encrypt_key(key, 128, &aesKey);

  size_t numBlocks = length / AES_BLOCK_SIZE;

  for (size_t i = 0; i < numBlocks + 1; ++i) {
    AES_encrypt(
        (const unsigned char *)(plaintext + i * AES_BLOCK_SIZE),
        (unsigned char*)(plaintext + i * AES_BLOCK_SIZE),
        &aesKey);
  }
}

void encrypt_DES(char* plaintext, size_t length, char* output, size_t *outlen) {
    int DES_BLOCK_SIZE = 8;
    const unsigned char* key = getkey();

    size_t numBlocks = (length + (DES_BLOCK_SIZE - 1)) / DES_BLOCK_SIZE;
    if (numBlocks * DES_BLOCK_SIZE > length) {
        memset(plaintext + length, 0, numBlocks * DES_BLOCK_SIZE - length);
    }

    DES_key_schedule ks1;

    unsigned char ke1[8], ivec[8];
    memcpy(ke1, key, 8);
    memcpy(ivec, "12345678", 8);

    DES_set_key_unchecked((const_DES_cblock*)ke1, &ks1);

    for (size_t i = 0; i < numBlocks; ++i) {
        DES_cbc_encrypt(
            (const unsigned char*)(plaintext + i * DES_BLOCK_SIZE),
            (unsigned char*)(output + i * DES_BLOCK_SIZE),
            DES_BLOCK_SIZE,
            &ks1, 
            (DES_cblock*)ivec, 
            DES_ENCRYPT);
    }
    
    *outlen = numBlocks * DES_BLOCK_SIZE;
}

/**
 * @brief Decryption function
 * Decrypts text using aes-128
 * @param {char*} plaintext text for decryption
 * @param {size_t} length text length
 */
void decrypt_AES(char *ciphertext, size_t length) {
  const unsigned char *key = getkey();

  AES_KEY aesKey;
  AES_set_decrypt_key(key, 128, &aesKey);

  size_t numBlocks = length / AES_BLOCK_SIZE;

  for (size_t i = 0; i < numBlocks + 1; ++i) {
    AES_decrypt(
        (const unsigned char*)(ciphertext +
                                                i * AES_BLOCK_SIZE),
        (unsigned char*)(ciphertext + i * AES_BLOCK_SIZE),
        &aesKey);
  }
}

void decrypt_DES(char* ciphertext, size_t length, char* output, size_t* outlen) {
    int DES_BLOCK_SIZE = 8;
    const unsigned char* key = getkey();

    size_t numBlocks = length / DES_BLOCK_SIZE;
    DES_key_schedule ks1;

    unsigned char ke1[8], ivec[8];
    memcpy(ke1, key, 8);
    memcpy(ivec, "12345678", 8);

    DES_set_key_unchecked((const_DES_cblock*)ke1, &ks1);

    for (size_t i = 0; i < numBlocks + 1; ++i) {
        DES_cbc_encrypt(
            (const unsigned char*)(ciphertext + i * DES_BLOCK_SIZE),
            (unsigned char*)(output + i * DES_BLOCK_SIZE),
            i < numBlocks ? DES_BLOCK_SIZE : length - numBlocks * DES_BLOCK_SIZE,
            &ks1,
            (DES_cblock*)ivec,
            DES_DECRYPT);
    }

    *outlen = numBlocks * DES_BLOCK_SIZE;
    if (numBlocks * DES_BLOCK_SIZE > length) {
        memset(output + length, 0, numBlocks * DES_BLOCK_SIZE - length);
    }
}