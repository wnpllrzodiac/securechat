#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "../include/cipher.h"
#include <stdexcept>

TEST_CASE("English")
{
    SUBCASE("1 test"){
        char plaintext[] = "Hello, world!!!";
        encrypt_AES(plaintext, sizeof(plaintext));
        decrypt_AES(plaintext, sizeof(plaintext));

        CHECK(std::strcmp(plaintext, "Hello, world!!!") == 0);
    }

    SUBCASE("2 test"){
        char plaintext[] = "w";
        encrypt_AES(plaintext, sizeof(plaintext));
        decrypt_AES(plaintext, sizeof(plaintext));

        CHECK(std::strcmp(plaintext, "w") == 0);
    }

    SUBCASE("3 test"){
        char plaintext[] = "!@#$%^**()~~~";
        encrypt_AES(plaintext, sizeof(plaintext));
        decrypt_AES(plaintext, sizeof(plaintext));

        CHECK(std::strcmp(plaintext, "!@#$%^**()~~~") == 0);
    }
   
}    

TEST_CASE("Rassian")
{
    SUBCASE("1 test"){
        char plaintext[] = "Привет мир!!!";
        encrypt_AES(plaintext, sizeof(plaintext));
        decrypt_AES(plaintext, sizeof(plaintext));

        CHECK(std::strcmp(plaintext, "Привет мир!!!") == 0);
    }


    SUBCASE("2 test"){
        char plaintext[] = "я";
        encrypt_AES(plaintext, sizeof(plaintext));
        decrypt_AES(plaintext, sizeof(plaintext));

        CHECK(std::strcmp(plaintext, "я") == 0);
    }

    SUBCASE("3 test"){
        char plaintext[] = "!№%:?*(*?:%№";
        encrypt_AES(plaintext, sizeof(plaintext));
        decrypt_AES(plaintext, sizeof(plaintext));

        CHECK(std::strcmp(plaintext, "!№%:?*(*?:%№") == 0);
    }
    
   
}   