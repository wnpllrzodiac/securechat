#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "../include/cipher.h"
#include <cstdio>
#include <cstring>
#include <iostream>
#include <thread>
#include <winsock2.h>

using namespace std;

// COLORS
#define CYN "\x1B[36m"
#define MAG "\x1B[35m"
#define BLU "\x1B[34m"
#define GRN "\x1B[32m"
#define RED "\x1B[31m"
#define WHT "\x1B[37m"
#define NRM "\x1B[0m"

enum MESSAGE_TYPE {
    MESSAGE_TYPE_LOGIN = 10,
    MESSAGE_TYPE_USERNAME = 20,
    MESSAGE_TYPE_MESSAGE = 30,
    MESSAGE_TYPE_EXIT = 40,
};

string readme(string username) {
    string s = BLU;
    s += "[server]: Welcome to Safe Chat, " + username + " \n";
    s += "          Commands > \n";
    s += "          status:              Lists the status of all users.\n";
    s += "          connect [username]:  Connect To User [username].\n";
    s += "          goodbye:             End the current chatting session.\n";
    s += "          close:               Disconnect from the user from the server\n";
    s += "          clear:               Clears the chat from the window.\n";
    s += NRM;
    return s;
}

int g_uid = -1;

/**
 * @brief Function to receive data from the server and decrypt it using AES-128.
 * @param {SOCKEt} server The server socket to receive data from.
 */
void clientReceive(SOCKET server) {
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

        if ((readed = recv(server, buffer + offset, toread, 0)) == SOCKET_ERROR) {
            cout << "recv function failed with error " << WSAGetLastError() << endl;
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
        std::cout << "msg type: " << msg_type << ", msg_len: " << payload_len << ", from: " << msg_from << ", to: " << msg_to << std::endl;

        offset += readed;
        if (offset < 13 + payload_len) {
            // not enough data
            curr_payload_len = payload_len;
            continue;
        }

        switch (msg_type) {
        case MESSAGE_TYPE_LOGIN:
            cout << "Login message received" << endl;
            decrypt_AES(buffer + 13, offset - 13);
            int uid;
            memcpy(&uid, buffer + 13, 4);
            cout << "Your user id is: " << uid << endl;
            g_uid = uid;
            break;
        case MESSAGE_TYPE_MESSAGE:
            decrypt_AES(buffer + 13, offset - 13);
            cout << "Server msg: " << buffer + 13;
            break;
        default:
            break;
        }

        memset(buffer, 0, sizeof(buffer));
        offset = 0;
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

    cout << readme(username);

    encrypt_AES(username, strlen(username));
    
    buffer[0] = MESSAGE_TYPE_USERNAME;
    // fix buffer[1] to buffer[4] with the length of the username
    int size = strlen(username);
    memcpy(buffer + 9, &size, 4);
    memcpy(buffer + 13, username, strlen(username));
    int msg_len = 13 + strlen(username);
    cout << "msg_len: " << msg_len << endl;

    if (send(server, buffer, msg_len, 0) == SOCKET_ERROR) {
        cout << "send failed with error: " << WSAGetLastError() << endl;
        return;
    }

    int to_uid = -1;
    while (true) {
        fgets(msg, 4096, stdin);
        if (strstr(msg, "connect") == msg) {
            sscanf(msg, "connect %d", &to_uid);
            cout << "set to_user to: " << to_uid << endl;
            continue;
        }

        if (to_uid == -1) {
			cout << "Please connect to a user first" << endl;
			continue;
		}

        encrypt_AES(msg, strlen(msg));

        memset(buffer, 0, 4096);
        buffer[0] = MESSAGE_TYPE_MESSAGE;
        // fix buffer[1] to buffer[4] with the length of the username
        int size = strlen(msg);
        memcpy(buffer + 1, &g_uid, 4); // from user id
        memcpy(buffer + 5, &to_uid, 4); // to user id
        memcpy(buffer + 9, &size, 4);
        memcpy(buffer + 13, msg, strlen(msg));
        int msg_len = 13 + strlen(msg);

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
