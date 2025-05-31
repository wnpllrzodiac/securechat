#ifndef RSA_UTIL_H
#define RSA_UTIL_H

#include <string>
#include <vector>

struct MyRSA;

MyRSA* generate_rsa_key(int key_size);
std::string extract_public_key(MyRSA* rsa_key);
std::vector<unsigned char> rsa_encrypt(const std::string& plaintext, MyRSA* public_key);
std::string rsa_decrypt(const std::vector<unsigned char>& ciphertext, MyRSA* private_key);

#endif