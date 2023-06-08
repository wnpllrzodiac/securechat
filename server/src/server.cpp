#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <cstdio>
#include <cstring>
#include <winsock2.h>
#include <thread>
#include "../include/cipher.h"

using namespace std;

/**
 * @brief Function to receive data from the client, decrypt it using AES-128, and display it.
 * 
 * @param {SOCKET} client The client socket to receive data from.
 */
void serverReceive(SOCKET client) {
    char buffer[1024] = { 0 };
    while (true) {
        if (recv(client, buffer, sizeof(buffer), 0) == SOCKET_ERROR) {
            cout << "recv function failed with error " << WSAGetLastError() << endl;
            return;
        }
        decrypt_AES(buffer, strlen(buffer));
        if (strcmp(buffer, "exit\n") == 0) {
            cout << "Client Disconnected." << endl;
            break;
        }
        cout << "Client: " << buffer;
        memset(buffer, 0, sizeof(buffer));
    }
}

/**
 * @brief Function to get input from the server, encrypt it using AES-128, and send it to the client.
 * 
 * @param {SOCKET} client The client socket to send data to.
 */
void serverSend(SOCKET client) {
    char buffer[1024] = { 0 };
    while (true) {
        fgets(buffer, 1024, stdin);
        encrypt_AES(buffer, strlen(buffer));
        if (send(client, buffer, sizeof(buffer), 0) == SOCKET_ERROR) {
            cout << "send failed with error " << WSAGetLastError() << endl;
            return;
        }
        if (strcmp(buffer, "exit\n") == 0) {
            cout << "Thank you for using the application" << endl;
            break;
        }
    }
}

/**
 * @brief Main function to create a server, accept client connections, and start the chat application.
 * 
 * @return {int} Exit status of the application.
 */
int main() {
    WSADATA WSAData;
    SOCKET server, client;
    SOCKADDR_IN serverAddr, clientAddr;
    if (WSAStartup(MAKEWORD(2, 0), &WSAData) != 0) {
        cout << "Error WSAStartup: " << WSAGetLastError() << endl;
        return -1;
    }
    server = socket(AF_INET, SOCK_STREAM, 0);
    if (server == INVALID_SOCKET) {
        cout << "Error initialization socket: " << WSAGetLastError() << endl;
        return -1;
    }
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(5555);
    if (bind(server, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        cout << "Bind function failed with error: " << WSAGetLastError() << endl;
        return -1;
    }

    if (listen(server, 0) == SOCKET_ERROR) {
        cout << "Listen function failed with error: " << WSAGetLastError() << endl;
        return -1;
    }
    cout << "Listening for incoming connections...." << endl;

    int clientAddrSize = sizeof(clientAddr);
    if ((client = accept(server, (SOCKADDR*)&clientAddr, &clientAddrSize)) != INVALID_SOCKET) {
        cout << "Client connected!" << endl;
        cout << "Now you can use our live chat application. " << "Enter \"exit\" to disconnect" << endl;

        thread t1(serverReceive, client);
        thread t2(serverSend, client);

        t1.join();
        t2.join();

        closesocket(client);
        if (closesocket(server) == SOCKET_ERROR) {
            cout << "Close socket failed with error: " << WSAGetLastError() << endl;
            return -1;
        }
        WSACleanup();
    }
}
