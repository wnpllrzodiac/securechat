cmake_minimum_required(VERSION 3.10)
project(server)

set(CMAKE_CXX_STANDARD 11)

find_package(OpenSSL REQUIRED)
find_package(SQLiteCpp REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})


add_executable(server src/server.cpp src/cipher.c)


target_link_libraries(server PRIVATE wsock32 ws2_32)
target_link_libraries(server PRIVATE ${OPENSSL_LIBRARIES} SQLiteCpp)

add_subdirectory(tests)

include(CTest)
enable_testing()



configure_file(../key.txt ${CMAKE_CURRENT_BINARY_DIR}/Debug/key.txt COPYONLY)
