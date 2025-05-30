#ifndef RSA_UTIL_H
#define RSA_UTIL_H

#include <openssl/rsa.h>
#include <string>
#include <vector>

struct RSA;

RSA* generate_rsa_key(int key_size);
std::string extract_public_key(RSA* rsa_key);
std::vector<unsigned char> rsa_encrypt(const std::string& plaintext, RSA* public_key);
std::string rsa_decrypt(const std::vector<unsigned char>& ciphertext, RSA* private_key);

#endif