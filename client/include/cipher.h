#ifndef CIPHER_01_H
#define CIPHER_01_H

const unsigned char *getkey();
void encrypt_AES(char *plaintext, size_t length);
void decrypt_AES(char *ciphertext, size_t length);
void encrypt_DES(char* plaintext, size_t length, char* output, size_t* outlen);
void decrypt_DES(char* ciphertext, size_t length, char* output, size_t* outlen);

#endif
