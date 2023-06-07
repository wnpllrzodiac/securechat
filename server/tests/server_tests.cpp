#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest/doctest/doctest.h"
#include "../include/server.h"
#include <stdexcept>
#include <iostream>
#include <thread>
#include <string>
#include <vector>

using namespace std;

TEST_CASE("serverReceive - Successful receive") {
    // Создаем сокет для клиента
    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(clientSocket != INVALID_SOCKET);

    // Создаем фейковый буфер с данными
    const char* testData = "Hello, server!";
    size_t testDataSize = strlen(testData);

    // Моделируем успешное получение данных от клиента
    int result = serverReceive(reinterpret_cast<LPVOID>(&clientSocket));
    REQUIRE(result == 1); // Успешное получение данных

    // Закрываем сокет клиента
    closesocket(clientSocket);
}