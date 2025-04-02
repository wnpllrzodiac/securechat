#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "../include/cipher.h"
#include <cstdio>
#include <cstring>
#include <iostream>
#include <thread>
#include <vector>
#include <winsock2.h>
#include "aixlog.hpp"

using namespace std;

struct ClientInfo {
    int         id;
    std::string username;
    SOCKET      client;
};

std::vector<ClientInfo> userList;

enum MESSAGE_TYPE {
    MESSAGE_TYPE_LOGIN = 10,
    MESSAGE_TYPE_USERNAME = 20,
    MESSAGE_TYPE_MESSAGE = 30,
    MESSAGE_TYPE_EXIT = 40,
};

/*
1 byte: message type
4 bytes: from
4 bytes: to
4 bytes: message length: little endian
n bytes: message
*/

void serverSendLoginMessage(SOCKET client, int uid);
void serverForwardMessage(int from, int to, char* encrypted_message, int len);

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
    int curr_payload_len = -1;

    while (true) {
        int toread = MAX_BUFFER_SIZE - offset;
        if (curr_payload_len > 0) {
            toread = curr_payload_len - (offset - 13);
        }

        if ((readed = recv(client, buffer + offset, toread, 0)) == SOCKET_ERROR) {
            LOG(INFO) << "recv function failed with error " << WSAGetLastError() << endl;
            return;
        }

        if (readed < 13) {
            offset += readed;
            continue;
        }

        int msg_type = buffer[0];
        int msg_from = *(int*)(buffer + 1);
        int msg_to = *(int*)(buffer + 5);
        int payload_len = *(int*)(buffer + 9);
        LOG(INFO) << "msg type: " << msg_type << ", msg_len: " << payload_len << ", from: " << msg_from << ", to: " << msg_to << std::endl;

        offset += readed;
        if (offset < 13 + payload_len) {
            // not enough data
            curr_payload_len = payload_len;
            continue;
        }

        int uid = -1;
        switch (msg_type) {
        case MESSAGE_TYPE_USERNAME:
            decrypt_AES(buffer + 13, offset - 13);
            uid = (int)userList.size();
            userList.push_back({ uid, std::string(buffer + 13), client});
            LOG(INFO) << "Client #" << uid << ": " <<  buffer + 13 << " added to list\n";

            serverSendLoginMessage(client, uid);

            break;
        case MESSAGE_TYPE_MESSAGE:
            LOG(INFO) << "Client msg(encrypted): " << buffer + 13 << ", to: " << msg_to << "\n";

            if (msg_to == -1) {
                // broadcast
                decrypt_AES(buffer + 13, offset - 13);
                LOG(INFO) << "broadcast msg: " << buffer + 13 << "\n";
            }
            else {
                // p2p
                serverForwardMessage(msg_from, msg_to, buffer + 13, offset - 13);
            }

            break;
        case MESSAGE_TYPE_EXIT:
            LOG(INFO) << "Client Disconnected.";
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
void serverSendLoginMessage(SOCKET client, int uid) {
    char buffer[1024] = {0};
    buffer[0] = MESSAGE_TYPE_LOGIN;
    memset(buffer + 1, 0, 4);
    memset(buffer + 5, 0, 4);
    int size = 0;
    memcpy(buffer + 9, &size, 4);

    char tmp[64] = { 0 };
    memcpy(tmp, &uid, 4);
    encrypt_AES(tmp, 4);
    
    memcpy(buffer + 13, tmp, strlen(tmp));

    if (send(client, buffer, 13 + strlen(tmp), 0) == SOCKET_ERROR) {
        LOG(ERROR) << "send failed with error: " << WSAGetLastError() << endl;
    }
}

void serverForwardMessage(int from, int to, char* encrypted_message, int len) {
    char buffer[1024] = { 0 };
    buffer[0] = MESSAGE_TYPE_MESSAGE;
    memcpy(buffer + 1, &from, 4);
    memcpy(buffer + 5, &to, 4);
    memcpy(buffer + 9, &len, 4);

    memcpy(buffer + 13, encrypted_message, len);

    for (auto cli : userList) {
        if (cli.id == to) {
            if (send(cli.client, buffer, 13 + len, 0) == SOCKET_ERROR) {
                LOG(ERROR) << "send failed with error " << WSAGetLastError() << endl;
			}

            LOG(INFO) << "message forwarded to: " << to;

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
  auto sink_cout = make_shared<AixLog::SinkCout>(AixLog::Severity::info);
  auto sink_file = make_shared<AixLog::SinkFile>(AixLog::Severity::info, "server.log");
  AixLog::Log::init({ sink_cout, sink_file });
  LOG(INFO) << "Hello, World!\n";

  WSADATA WSAData;
  SOCKET server, client;
  SOCKADDR_IN serverAddr, clientAddr;
  if (WSAStartup(MAKEWORD(2, 0), &WSAData) != 0) {
    cout << "Error WSAStartup: " << WSAGetLastError() << endl;
    LOG(ERROR) << "Error WSAStartup" << WSAGetLastError();
    return -1;
  }
  server = socket(AF_INET, SOCK_STREAM, 0);
  if (server == INVALID_SOCKET) {
    cout << "Error initialization socket: " << WSAGetLastError() << endl;
    LOG(ERROR) << "Error initialization socket: " << WSAGetLastError();
    return -1;
  }
  serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(6666);
  if (::bind(server, (SOCKADDR *)&serverAddr, sizeof(serverAddr)) ==
      SOCKET_ERROR) {
    cout << "Bind function failed with error: " << WSAGetLastError() << endl;
    LOG(ERROR) << "Bind function failed with error: " << WSAGetLastError();
    return -1;
  }

  if (::listen(server, 0) == SOCKET_ERROR) {
    cout << "Listen function failed with error: " << WSAGetLastError() << endl;
    LOG(ERROR) << "Listen function failed with error: " << WSAGetLastError();
    return -1;
  }
  LOG(INFO) << "Listening for incoming connections...." << endl;

  int clientAddrSize = sizeof(clientAddr);
  while ((client = ::accept(server, (SOCKADDR *)&clientAddr, &clientAddrSize)) != INVALID_SOCKET) {
    LOG(INFO) << "Client connected!" << endl;
    LOG(INFO) << "Now you can use our live chat application. "
         << "Enter \"exit\" to disconnect" << endl;
    LOG(INFO) << "Client connected!\n";

    thread t1(serverReceive, client);
    t1.detach();
  }

  WSACleanup();
}
