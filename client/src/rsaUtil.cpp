#include "../include/rsaUtil.h"
#include <iostream>
#include <string>
#include <vector>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdexcept>

struct MyRSA {
    MyRSA(RSA* rsa) : rsa_(rsa) { }
    RSA* rsa_;
};

// 错误处理函数
void handle_errors() {
    ERR_print_errors_fp(stderr);
    throw std::runtime_error("OpenSSL error occurred");
}

// 生成 RSA 密钥对
MyRSA* generate_rsa_key(int key_size) {
    RSA* rsa = RSA_new();
    if (!rsa) handle_errors();

    BIGNUM* bne = BN_new();
    if (!bne) {
        RSA_free(rsa);
        handle_errors();
    }

    if (!BN_set_word(bne, RSA_F4)) { // RSA_F4 is 65537, the common public exponent
        BN_free(bne);
        RSA_free(rsa);
        handle_errors();
    }

    if (!RSA_generate_key_ex(rsa, key_size, bne, NULL)) {
        BN_free(bne);
        RSA_free(rsa);
        handle_errors();
    }

    BN_free(bne);
    return new MyRSA(rsa);
}

// 提取公钥
std::string extract_public_key(MyRSA* rsa_key) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) handle_errors();

    if (!PEM_write_bio_RSAPublicKey(bio, rsa_key->rsa_)) {
        BIO_free_all(bio);
        handle_errors();
    }

    int len = BIO_pending(bio);
    std::vector<char> buffer(len + 1);
    BIO_read(bio, buffer.data(), len);
    buffer[len] = '\0';

    BIO_free_all(bio);
    return std::string(buffer.data(), len);
}

// 提取私钥
std::string extract_private_key(MyRSA* rsa_key) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) handle_errors();

    if (!PEM_write_bio_RSAPrivateKey(bio, rsa_key->rsa_, NULL, NULL, 0, NULL, NULL)) {
        BIO_free_all(bio);
        handle_errors();
    }

    int len = BIO_pending(bio);
    std::vector<char> buffer(len + 1);
    BIO_read(bio, buffer.data(), len);
    buffer[len] = '\0';

    BIO_free_all(bio);
    return std::string(buffer.data(), len);
}

// 从公钥字符串创建 RSA 结构体
MyRSA* create_rsa_from_pub_key_string(const std::string& pub_key_string) {
    RSA* rsa = nullptr;
    BIO* keybio = BIO_new_mem_buf((void*)pub_key_string.c_str(), pub_key_string.size()); // -1: string is null-terminated

    if (keybio == nullptr) {
        std::cerr << "Failed to create BIO from public key string." << std::endl;
        return nullptr;
    }

    rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, nullptr, nullptr);

    if (rsa == nullptr) {
        unsigned long ulErr = ERR_get_error();
        ERR_print_errors_fp(stderr); // Print OpenSSL error messages to stderr
        std::cerr << "Failed to create RSA struct from public key string." << std::endl;
        BIO_free(keybio); // Always free BIO
        return nullptr;
    }

    BIO_free(keybio); // Always free BIO
    return new MyRSA(rsa);
}

// 从私钥字符串创建 RSA 结构体
MyRSA* createRSA(const std::string& privateKeyString) {
    RSA* rsa = nullptr;
    BIO* keybio = BIO_new_mem_buf((void*)privateKeyString.c_str(), -1);  // 创建 BIO 对象
    if (!keybio) {
        handle_errors();
        return nullptr;
    }

    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, nullptr, nullptr); // 从 BIO 对象读取 RSA 私钥

    if (!rsa) {
        handle_errors();
        BIO_free_all(keybio);  // 释放 BIO 资源
        return nullptr;
    }

    BIO_free_all(keybio);  // 释放 BIO 资源
    return new MyRSA(rsa);
}

// RSA 加密
std::vector<unsigned char> rsa_encrypt(const std::string& plaintext, MyRSA* public_key) {
    int key_size = RSA_size(public_key->rsa_);
    std::vector<unsigned char> ciphertext(key_size);

    int result = RSA_public_encrypt(
        plaintext.size(),
        reinterpret_cast<const unsigned char*>(plaintext.data()),
        ciphertext.data(),
        public_key->rsa_,
        RSA_PKCS1_PADDING // 使用 PKCS#1 v1.5 padding
    );

    if (result == -1) {
        handle_errors();
    }
    ciphertext.resize(result); // Resize to actual ciphertext size.

    return ciphertext;
}

// RSA 解密
std::string rsa_decrypt(const std::vector<unsigned char>& ciphertext, MyRSA* private_key) {
    int key_size = RSA_size(private_key->rsa_);
    std::vector<unsigned char> plaintext(key_size);

    int result = RSA_private_decrypt(
        ciphertext.size(),
        ciphertext.data(),
        plaintext.data(),
        private_key->rsa_,
        RSA_PKCS1_PADDING // 使用 PKCS#1 v1.5 padding
    );

    if (result == -1) {
        handle_errors();
    }

    plaintext.resize(result); // Resize to actual plaintext size
    return std::string(plaintext.begin(), plaintext.end());
}

int test_main()
{
    // 初始化 OpenSSL 错误信息
    OpenSSL_add_all_algorithms(); //加载所有算法
    ERR_load_crypto_strings();

    try {
        // 1. 生成 RSA 密钥对 (2048 位)
        MyRSA* rsa_key = generate_rsa_key(2048);
        
        std::string public_key = extract_public_key(rsa_key);
		std::string private_key = extract_private_key(rsa_key);
        printf("pub: %s\n", public_key.c_str());
		printf("pri: %s\n", private_key.c_str());

        // 2. 准备要加密的数据
        std::string plaintext = "This is a secret message!";

        // 3. 加密
        MyRSA* rsa_key_pub = create_rsa_from_pub_key_string(public_key); // 创建 RSA 结构体从公钥字符串
        std::vector<unsigned char> ciphertext = rsa_encrypt(plaintext, rsa_key_pub);

        // 4. 解密
        std::string decrypted_text = rsa_decrypt(ciphertext, rsa_key);

        // 5. 输出结果
        std::cout << "Original text: " << plaintext << std::endl;
        std::cout << "Ciphertext (hex): ";
        for (unsigned char c : ciphertext) {
            printf("%02x", c);
        }
        std::cout << std::endl;
        std::cout << "Decrypted text: " << decrypted_text << std::endl;

        // 6. 释放密钥
        RSA_free(rsa_key->rsa_);
        EVP_cleanup();
        CRYPTO_cleanup_all_ex_data();
        ERR_free_strings();

    }
    catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
