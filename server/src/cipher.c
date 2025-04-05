//#include <cstring>
//#include <fstream>
//#include <iostream>
#include <openssl/aes.h>
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
  return defaultKey;
  */
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
        (const unsigned char*)(plaintext + i * AES_BLOCK_SIZE),
        (unsigned char*)(plaintext + i * AES_BLOCK_SIZE),
        &aesKey);
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
