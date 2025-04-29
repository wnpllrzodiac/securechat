//#include <cstring>
//#include <fstream>
//#include <iostream>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <stdio.h>
//#include <string>

extern char g_key[16];

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
  return defaultKey;
  */
    //return "1234567890abcdef";
    return g_key;
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
        (const unsigned char*)(plaintext + i * AES_BLOCK_SIZE),
        (unsigned char*)(plaintext + i * AES_BLOCK_SIZE),
        &aesKey);
  }
}

#define DES_BLOCK_SIZE 8
void encrypt_DES_File(char* filepath, char* encfilepath)
{
    const unsigned char* key = getkey();

    unsigned char indata[DES_BLOCK_SIZE] = {0};
    unsigned char outdata[DES_BLOCK_SIZE] = { 0 };

    FILE* pFile = NULL;
    pFile = fopen(filepath, "rb");
    if (pFile == NULL)
        return;

    FILE* pEncryptedFile = NULL;
    pEncryptedFile = fopen(encfilepath, "wb");
    if (pEncryptedFile == NULL)
        return;

    DES_key_schedule ks1;

    unsigned char ke1[8], ivec[8];
    memcpy(ke1, key, 8);
    memcpy(ivec, "12345678", 8);

    DES_set_key_unchecked((const_DES_cblock*)ke1, &ks1);

    int bytes_read;
    int bytes_written;
    while (1) {
        memset(indata, DES_BLOCK_SIZE, 0);
        memset(outdata, DES_BLOCK_SIZE, 0);

        bytes_read = fread(indata, 1, DES_BLOCK_SIZE, pFile);

        DES_cbc_encrypt(
            (const unsigned char*)indata,
            outdata,
            DES_BLOCK_SIZE,
            &ks1,
            (DES_cblock*)ivec,
            DES_ENCRYPT);

        bytes_written = fwrite(outdata, 1, bytes_read, pEncryptedFile);

        if (bytes_read < DES_BLOCK_SIZE)
            break;
    }
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
