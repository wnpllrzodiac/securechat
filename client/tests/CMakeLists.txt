cmake_minimum_required(VERSION 3.10)
project(client_tests)

set(CMAKE_CXX_STANDARD 11)

find_package(OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})


add_executable(client_tests ../src/cipher.c cipher_tests.cpp)


target_link_libraries(client_tests PRIVATE wsock32 ws2_32)
target_link_libraries(client_tests PRIVATE ${OPENSSL_LIBRARIES})


include(CTest)
enable_testing()

add_test(NAME client_tests COMMAND client_tests)

configure_file(../../key.txt ${CMAKE_CURRENT_BINARY_DIR}/Debug/key.txt COPYONLY)