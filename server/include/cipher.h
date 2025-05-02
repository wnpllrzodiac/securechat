#ifndef CIPHER_01_H
#define CIPHER_01_H

#ifdef __cplusplus
extern "C" {
#endif

const unsigned char *getkey();
int encrypt_AES(unsigned char* input, int len, unsigned char* output, int* outlen);
int decrypt_AES(unsigned char* input, int len, unsigned char* output, int* outlen);
void encrypt_DES_File(char* filepath, char* encfilepath);

#ifdef __cplusplus
}
#endif

#endif
