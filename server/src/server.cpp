#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "../include/cipher.h"
#include <cstdio>
#include <cstring>
#include <iostream>
#include <thread>
#include <vector>
#include <winsock2.h>


using namespace std;

struct ClientInfo {
    std::string username;
    SOCKET client;
};

std::vector<ClientInfo> userList;

/*
1 byte: message type:    1-username, 2-message, 3-exit
4 bytes: message length: little endian
n bytes: message
*/

/**
 * @brief Function to receive data from the client, decrypt it using AES-128,
 * and display it.
 * @param {SOCKET} client The client socket to receive data from.
 */
void serverReceive(SOCKET client) {
    const int MAX_BUFFER_SIZE = 4096;
    char buffer[MAX_BUFFER_SIZE] = {0};
    int offset = 0;
    int readed = -1;
    int curr_msg_len = -1;

    while (true) {
        int toread = MAX_BUFFER_SIZE - offset;
        if (curr_msg_len > 0) {
            toread = curr_msg_len - (offset - 1 - 5);
        }

        if ((readed = recv(client, buffer + offset, toread, 0)) == SOCKET_ERROR) {
            cout << "recv function failed with error " << WSAGetLastError() << endl;
            return;
        }

        if (readed < 5) {
            offset += readed;
            continue;
        }

        int msg_type = buffer[0];
        int msg_len = *(int *)(buffer + 1);
        std::cout << "msg type: " << msg_type << ", msg_len: " << msg_len << std::endl;

        offset += readed;
        if (offset < 1 + 4 + msg_len) {
            // not enough data
            curr_msg_len = msg_len;
            continue;
        }

        switch (msg_type) {
        case 1:
            decrypt_AES(buffer + 5, offset - 5);
            userList.push_back({std::string(buffer + 5), client});
            std::cout << "Client " << buffer + 5 << " added to list" << std::endl;
            break;
        case 2:
            decrypt_AES(buffer + 5, offset - 5);
            cout << "Client msg: " << buffer + 5;
            break;
        case 3:
            cout << "Client Disconnected." << endl;
            break;
        default:
            break;
        }

        memset(buffer, 0, sizeof(buffer));
        offset = 0;
    }
}

/**
 * @brief Function to get input from the server, encrypt it using AES-128, and
 * send it to the client.
 * @param {SOCKET} client The client socket to send data to.
 */
void serverSend(SOCKET client) {
  char buffer[1024] = {0};
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
 * @brief Main function to create a server, accept client connections, and start
 * the chat application.
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
  serverAddr.sin_port = htons(6666);
  if (bind(server, (SOCKADDR *)&serverAddr, sizeof(serverAddr)) ==
      SOCKET_ERROR) {
    cout << "Bind function failed with error: " << WSAGetLastError() << endl;
    return -1;
  }

  if (listen(server, 0) == SOCKET_ERROR) {
    cout << "Listen function failed with error: " << WSAGetLastError() << endl;
    return -1;
  }
  cout << "Listening for incoming connections...." << endl;

  int clientAddrSize = sizeof(clientAddr);
  if ((client = accept(server, (SOCKADDR *)&clientAddr, &clientAddrSize)) !=
      INVALID_SOCKET) {
    cout << "Client connected!" << endl;
    cout << "Now you can use our live chat application. "
         << "Enter \"exit\" to disconnect" << endl;

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
