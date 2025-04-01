cmake_minimum_required(VERSION 3.10)
project(server_tests)

set(CMAKE_CXX_STANDARD 11)

find_package(OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})


add_executable(server_tests ../src/cipher.cpp  cipher_tests.cpp)


target_link_libraries(server_tests PRIVATE wsock32 ws2_32)
target_link_libraries(server_tests PRIVATE ${OPENSSL_LIBRARIES})


include(CTest)
enable_testing()

add_test(NAME server_tests COMMAND server_tests)

configure_file(../../key.txt ${CMAKE_CURRENT_BINARY_DIR}/Debug/key.txt COPYONLY)