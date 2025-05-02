//#include <cstring>
//#include <fstream>
//#include <iostream>
#include <openssl/aes.h>
#include <openssl/des.h>
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
  return defaultKey;*/
    return g_key;
}

// PKCS#7 填充函数
void pkcs7_pad(unsigned char* input, size_t input_len, unsigned char* output, size_t* output_len) {
    size_t padding = AES_BLOCK_SIZE - (input_len % AES_BLOCK_SIZE); // 计算需要填充的字节数

    // 拷贝原始数据到输出缓冲区
    memcpy(output, input, input_len);

    // 填充数据
    for (size_t i = 0; i < padding; i++) {
        output[input_len + i] = (unsigned char)padding;
    }

    // 更新填充后的总长度
    *output_len = input_len + padding;
}

size_t pkcs7_unpad(unsigned char* input, size_t input_len) {
    unsigned char pad_value = input[input_len - 1]; // 获取填充值
    return input_len - pad_value; // 返回去除填充后的数据长度
}

int encrypt_AES(unsigned char* input, int len, unsigned char* output, int* outlen)
{
    unsigned char key[17] = "1234567890abcdef"; // 128 位密钥

    // 初始化 AES 密钥
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key); // 密钥长度为 128 位

    int groups = (len + 15) / AES_BLOCK_SIZE;
    printf("groups: %d\n", groups);

    for (int i = 0;i < groups;i++) {
        if (i == groups - 1) {
            // last group
            unsigned char padded_data[AES_BLOCK_SIZE * 2] = { 0 };
            size_t padded_len = 0;
            int input_len;
            if (len % AES_BLOCK_SIZE == 0)
                input_len = AES_BLOCK_SIZE;
            else
                input_len = len % AES_BLOCK_SIZE;
            pkcs7_pad(input + i * AES_BLOCK_SIZE, input_len, padded_data, &padded_len);

            // 打印填充后的数据
            printf("Padded data (hex): ");
            for (size_t i = 0; i < padded_len; i++) {
                printf("%02x ", padded_data[i]);
            }
            printf("\n");

            if (len % AES_BLOCK_SIZE == 0)
                *outlen = (len / AES_BLOCK_SIZE - 1) * AES_BLOCK_SIZE + padded_len;
            else
                *outlen = len / AES_BLOCK_SIZE * AES_BLOCK_SIZE + padded_len;

            AES_encrypt(padded_data, output + i * AES_BLOCK_SIZE, &aes_key);
            if (padded_len > AES_BLOCK_SIZE)
                AES_encrypt(padded_data + AES_BLOCK_SIZE, output + (i + 1) * AES_BLOCK_SIZE, &aes_key);
        }
        else {
            AES_encrypt(input + i * AES_BLOCK_SIZE, output + i * AES_BLOCK_SIZE, &aes_key);
        }
    }

    return 0;
}

int decrypt_AES(unsigned char* input, int len, unsigned char* output, int* outlen)
{
    unsigned char key[17] = "1234567890abcdef"; // 128 位密钥

    // 初始化 AES 密钥
    AES_KEY aes_key;
    AES_set_decrypt_key(key, 128, &aes_key); // 密钥长度为 128 位

    int groups = len / AES_BLOCK_SIZE;

    for (int i = 0;i < groups;i++) {
        AES_decrypt(input + i * AES_BLOCK_SIZE, output + i * AES_BLOCK_SIZE, &aes_key);

        if (i == groups - 1) {
            unsigned char pad_value = output[(i + 1) * AES_BLOCK_SIZE - 1];
            int is_padding = 1;
            for (int k = groups * AES_BLOCK_SIZE - 1; k > groups * AES_BLOCK_SIZE - 1 - pad_value; k--) {
                if (output[k] != pad_value) {
                    printf("pkcs7 error\n");
                    return -1;
                }
            }

            printf("padding len: %d\n", pad_value);
            memset(output + (i + 1) * AES_BLOCK_SIZE - pad_value, 0, pad_value);
            *outlen = len - pad_value;
        }
    }

    return 0;
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