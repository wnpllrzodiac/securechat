#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream> 
#include <cstdio> 
#include <cstring> 
#include <winsock2.h> 
#include <thread> 
#include "../include/cipher.h"

using namespace std;

/**
 * @brief Function to receive data from the server and decrypt it using AES-128.
 * 
 * @param {SOCKEt} server The server socket to receive data from.
 */
void clientReceive(SOCKET server) 
{
    char buffer[1024] = { 0 };
    while (true) 
    {
        if (recv(server, buffer, sizeof(buffer), 0) == SOCKET_ERROR) 
        {
            cout << "recv function failed with error: " << WSAGetLastError() << endl;
            return;
        }
        decrypt_AES(buffer, strlen(buffer));
        if (strcmp(buffer, "exit\n") == 0)
        {
            cout << "Server disconnected." << endl;
            return;
        }
        cout << "Server: " << buffer;
        memset(buffer, 0, sizeof(buffer));
    }
}

/**
 * @brief Function to send data to the server after encrypting it using AES-128.
 * 
 * @param {SOCKET} server The server socket to send data to.
 */
void clientSend(SOCKET server) 
{
    char buffer[1024] = { 0 };
    while (true) 
    {
        fgets(buffer, 1024, stdin);
        encrypt_AES(buffer, strlen(buffer));
        if (send(server, buffer, sizeof(buffer), 0) == SOCKET_ERROR) 
        {
            cout << "send failed with error: " << WSAGetLastError() << endl;
            return;
        }
        if (strcmp(buffer, "exit") == 0) 
        {
            cout << "Thank you for using the application" << endl;
            break;
        }
    }
}

/**
 * @brief Main function to establish a connection with the server and start the client chat application.
 * 
 * @return {int} Exit status of the application.
 */
int main() 
{
    WSADATA WSAData;
    SOCKET server;
    SOCKADDR_IN addr;
    WSAStartup(MAKEWORD(2, 2), &WSAData);
    if ((server = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) 
    {
        cout << "Socket creation failed with error: " << WSAGetLastError() << endl;
        return -1;
    }
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_family = AF_INET;
    addr.sin_port = htons(5555);
    if (connect(server, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR) 
    {
        cout << "Server connection failed with error: " << WSAGetLastError() << endl;
        return -1;
    }

    cout << "Connected to server!" << endl;
    cout << "Now you can use our live chat application. "  << " Enter \"exit\" to disconnect" << endl;

    thread t1(clientReceive, server);
    thread t2(clientSend, server);

    t1.join();
    t2.join();

    closesocket(server);
    WSACleanup();
}
