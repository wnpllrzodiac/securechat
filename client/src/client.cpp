#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "../include/cipher.h"
#include <cstdio>
#include <cstring>
#include <iostream>
#include <thread>
#include <winsock2.h>

using namespace std;

struct ClientInfo {
    std::string username;
    SOCKET client;
};

/**
 * @brief Function to receive data from the server and decrypt it using AES-128.
 * @param {SOCKEt} server The server socket to receive data from.
 */
void clientReceive(SOCKET server) {
  char buffer[1024] = {0};
  while (true) {
    if (recv(server, buffer, sizeof(buffer), 0) == SOCKET_ERROR) {
      cout << "recv function failed with error: " << WSAGetLastError() << endl;
      return;
    }
    decrypt_AES(buffer, strlen(buffer));
    if (strcmp(buffer, "exit\n") == 0) {
      cout << "Server disconnected." << endl;
      return;
    }
    cout << "Server: " << buffer;
    memset(buffer, 0, sizeof(buffer));
  }
}

/**
 * @brief Function to send data to the server after encrypting it using AES-128.
 * @param {SOCKET} server The server socket to send data to.
 */
void clientSend(SOCKET server) {
    char buffer[4096] = { 0 };
    char username[64] = { 0 };
    char msg[4096] = { 0 };
    cout << "Enter your username: ";
    fgets(username, 64, stdin);
    encrypt_AES(username, strlen(username));
    
    buffer[0] = 1;
    // fix buffer[1] to buffer[4] with the length of the username
    int size = strlen(username);
    memcpy(buffer + 1, &size, 4);
    memcpy(buffer + 5, username, strlen(username));
    int msg_len = 1 + 5 + strlen(username);
    cout << "msg_len: " << msg_len << endl;

    if (send(server, buffer, msg_len, 0) == SOCKET_ERROR) {
        cout << "send failed with error: " << WSAGetLastError() << endl;
        return;
    }

    while (true) {
        fgets(msg, 4096, stdin);

        encrypt_AES(msg, strlen(msg));

        buffer[0] = 2;
        // fix buffer[1] to buffer[4] with the length of the username
        int size = strlen(msg);
        memcpy(buffer + 1, &size, 4);
        memcpy(buffer + 5, msg, strlen(msg));
        int msg_len = 5 + strlen(msg);

        if (send(server, buffer, msg_len, 0) == SOCKET_ERROR) {
            cout << "send failed with error: " << WSAGetLastError() << endl;
            return;
        }
        if (strcmp(buffer, "exit") == 0) {
            cout << "Thank you for using the application" << endl;
            break;
        }
    }
}

/**
 * @brief Main function to establish a connection with the server and start the
 * client chat application.
 * @return {int} Exit status of the application.
 */
int main() {
  WSADATA WSAData;
  SOCKET server;
  SOCKADDR_IN addr;
  WSAStartup(MAKEWORD(2, 2), &WSAData);
  if ((server = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
    cout << "Socket creation failed with error: " << WSAGetLastError() << endl;
    return -1;
  }
  addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  addr.sin_family = AF_INET;
  addr.sin_port = htons(6666);
  if (connect(server, (SOCKADDR *)&addr, sizeof(addr)) == SOCKET_ERROR) {
    cout << "Server connection failed with error: " << WSAGetLastError()
         << endl;
    return -1;
  }

  cout << "Connected to server!" << endl;
  cout << "Now you can use our live chat application. "
       << " Enter \"exit\" to disconnect" << endl;

  thread t1(clientReceive, server);
  thread t2(clientSend, server);

  t1.join();
  t2.join();

  closesocket(server);
  WSACleanup();
}
