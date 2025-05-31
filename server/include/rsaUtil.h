#ifndef RSA_UTIL_H
#define RSA_UTIL_H

#include <string>
#include <vector>

struct MyRSA;

MyRSA* generate_rsa_key(int key_size);
std::string extract_public_key(MyRSA* rsa_key);
MyRSA* create_rsa_from_pub_key_string(const std::string& pub_key_string);
std::vector<unsigned char> rsa_encrypt(const std::string& plaintext, MyRSA* public_key);
std::string rsa_decrypt(const std::vector<unsigned char>& ciphertext, MyRSA* private_key);

#endif