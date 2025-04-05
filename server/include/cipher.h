#ifndef CIPHER_01_H
#define CIPHER_01_H

#ifdef __cplusplus
extern "C" {
#endif

const unsigned char *getkey();
void encrypt_AES(char *plaintext, size_t length);
void decrypt_AES(char *ciphertext, size_t length);

#ifdef __cplusplus
}
#endif

#endif
