cmake_minimum_required(VERSION 3.10)
project(client)

set(CMAKE_CXX_STANDARD 11)

find_package(OpenSSL REQUIRED)

find_package(Qt6 REQUIRED COMPONENTS Core)
find_package(Qt6 REQUIRED COMPONENTS Widgets)
find_package(Qt6 REQUIRED COMPONENTS Gui)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

include_directories(${OPENSSL_INCLUDE_DIR})


add_executable(client src/client.cpp src/cipher.cpp src/MainWnd.cpp)

target_link_libraries(client PRIVATE Qt6::Core Qt6::Gui Qt6::Widgets)
target_link_libraries(client PRIVATE wsock32 ws2_32)
target_link_libraries(client PRIVATE ${OPENSSL_LIBRARIES})

add_subdirectory(tests)

include(CTest)
enable_testing()


configure_file(../key.txt ${CMAKE_CURRENT_BINARY_DIR}/Debug/key.txt COPYONLY)