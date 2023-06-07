cmake_minimum_required(VERSION 3.10)
project(client)

set(CMAKE_CXX_STANDARD 11)

find_library(WS2_32_LIB NAMES WS2_32.lib)

find_package(OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})


add_executable(client src/client.cpp src/cipher.cpp)


target_link_libraries(client PRIVATE ${WS2_32_LIB})
target_link_libraries(client PRIVATE ${OPENSSL_LIBRARIES})

add_subdirectory(tests)

include(CTest)
enable_testing()

include(CPack)

configure_file(../key.txt ${CMAKE_CURRENT_BINARY_DIR}/Debug/key.txt COPYONLY)