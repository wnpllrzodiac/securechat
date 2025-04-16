#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "httplib.h"
#include "../include/cipher.h"
#include <cstdio>
#include <cstring>
#include <iostream>
#include <thread>
#include <vector>
#include <winsock2.h>
#include <SQLiteCpp/SQLiteCpp.h>
#include "aixlog.hpp"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

using namespace std;
using namespace httplib;

struct ClientInfo {
    int         id;
    std::string username;
    SOCKET      client;
};

std::vector<ClientInfo> userList;

enum MESSAGE_TYPE {
    MESSAGE_TYPE_LOGIN = 10,
    MESSAGE_TYPE_GETLIST,
    MESSAGE_TYPE_LIST,
    MESSAGE_TYPE_JOINED,
    MESSAGE_TYPE_LEAVED,
    MESSAGE_TYPE_LOGINRESULT = 20,
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

void serverSendUserList(SOCKET client);
void serverSendJoinedMessage(int uid, const char* username);
void serverSendLeavedMessage(int uid);
void serverSendLoginMessage(SOCKET client, int uid);
void serverForwardMessage(SOCKET socket, int from, int to, char* encrypted_message, int len);

int db_add_user(const char* username, const char* gender, int age, const char* email, const char* password);

/**
 * @brief Function to receive data from the client, decrypt it using AES-128,
 * and display it.
 * @param {SOCKET} client The client socket to receive data from.
 */
void serverReceive(SOCKET client) {
    const int MAX_BUFFER_SIZE = 4096;
    char buffer[MAX_BUFFER_SIZE] = {0};
    char decrypted[MAX_BUFFER_SIZE] = { 0 };
    int offset = 0;
    int readed = -1;
    int curr_payload_len = -1;

    while (true) {
        if (offset < 13) {
            int toread = MAX_BUFFER_SIZE - offset;
            if (curr_payload_len > 0) {
                toread = curr_payload_len - (offset - 13);
            }

            if ((readed = recv(client, buffer + offset, toread, 0)) == SOCKET_ERROR) {
                LOG(INFO) << "recv function failed with error " << WSAGetLastError() << endl;
                int leaved_uid = -1;
                for (std::vector<ClientInfo>::iterator it = userList.begin();it != userList.end(); ++it) {
                    if (it->client == client) {
                        leaved_uid = it->id;
                        it = userList.erase(it);
                        break;
                    }
                }

                serverSendLeavedMessage(leaved_uid);

                LOG(WARNING) << "recv thread exited" << std::endl;
                return;
            }

            offset += readed;

            if (readed < 13) {
                continue;
            }
        } 

        int msg_type = buffer[0];
        int msg_from = *(int*)(buffer + 1);
        int msg_to = *(int*)(buffer + 5);
        int payload_len = *(int*)(buffer + 9);
        LOG(INFO) << "msg type: " << msg_type << ", msg_len: " << payload_len << ", from: " << msg_from << ", to: " << msg_to << std::endl;

        if (offset < 13 + payload_len) {
            // not enough data
            curr_payload_len = payload_len;
            continue;
        }

        memset(decrypted, 0, MAX_BUFFER_SIZE);

        int uid = -1;
        switch (msg_type) {
        case MESSAGE_TYPE_USERNAME:
            memcpy(decrypted, buffer + 13, payload_len);
            decrypt_AES(decrypted, payload_len);
            uid = (int)userList.size();
            userList.push_back({ uid, std::string(decrypted), client});
            LOG(INFO) << "Client #" << uid << ": " << decrypted << " added to list\n";

            serverSendLoginMessage(client, uid);

            serverSendJoinedMessage(uid, decrypted);
            break;
        case MESSAGE_TYPE_MESSAGE:
            memcpy(decrypted, buffer + 13, payload_len);
            LOG(INFO) << "Client msg(encrypted): " << decrypted << ", to: " << msg_to << "\n";

            if (msg_to == -1) {
                // broadcast
                decrypt_AES(decrypted, payload_len);
                LOG(INFO) << "broadcast msg: " << decrypted << "\n";

                for (ClientInfo info : userList) {
                    if (info.id != msg_from) {
                        LOG(INFO) << "broadcast msg to: " << info.id << "\n";
						serverForwardMessage(info.client, msg_from, msg_to, buffer + 13, payload_len);
					}
                }
            }
            else {
                // p2p
                for (ClientInfo info : userList) {
                    if (info.id == msg_to) {
                        LOG(INFO) << "p2p msg to: " << info.id << "\n";
                        serverForwardMessage(info.client, msg_from, msg_to, buffer + 13, payload_len);
                        break;
                    }
                }
                
            }

            break;
        case MESSAGE_TYPE_GETLIST:
            serverSendUserList(client);
            break;
        case MESSAGE_TYPE_EXIT:
            LOG(INFO) << "Client Disconnected.";
            break;
        default:
            break;
        }

        if (offset > 13 + payload_len) {
            // more than one packet
            memmove(buffer, buffer + 13 + payload_len, offset - (13 + payload_len));
            cout << "more than one packet: " << offset - (13 + payload_len) << endl;
            offset -= (13 + payload_len);
        }
        else {
            memset(buffer, 0, sizeof(buffer));
            offset = 0;
        }
    }
}

void serverSendJoinedMessage(int uid, const char* username)
{
    char buffer[1024] = { 0 };
    buffer[0] = MESSAGE_TYPE_JOINED;
    int invalid_id = -1;
    memcpy(buffer + 1, &invalid_id, 4); // from
    memcpy(buffer + 5, &invalid_id, 4); // to

    int len = strlen(username);

    int payload_len = len + 4 + 4;
    memcpy(buffer + 9, &payload_len, 4);

    // 4 bytes: id, 4 bytes: size, n bytes: username
    memcpy(buffer + 13, &uid, 4);
    memcpy(buffer + 13 + 4, &len, 4);
    memcpy(buffer + 13 + 8, username, len);

    for (ClientInfo info : userList) {
        if (info.id != uid) {
            if (send(info.client, buffer, 13 + payload_len, 0) == SOCKET_ERROR) {
                LOG(ERROR) << "send failed with error: " << WSAGetLastError() << endl;
            }
        }
    }
}

void serverSendLeavedMessage(int uid)
{
    char buffer[1024] = { 0 };
    buffer[0] = MESSAGE_TYPE_LEAVED;
    int invalid_id = -1;
    memcpy(buffer + 1, &invalid_id, 4); // from
    memcpy(buffer + 5, &invalid_id, 4); // to

    int payload_len = 4;
    memcpy(buffer + 9, &payload_len, 4);

    // 4 bytes: id, 4 bytes: size, n bytes: username
    memcpy(buffer + 13, &uid, 4);

    for (ClientInfo info : userList) {
        if (info.id != uid) {
            if (send(info.client, buffer, 13 + payload_len, 0) == SOCKET_ERROR) {
                LOG(ERROR) << "send failed with error: " << WSAGetLastError() << endl;
            }
        }
    }
}

void serverSendUserList(SOCKET client)
{
    char buffer[1024] = { 0 };
    buffer[0] = MESSAGE_TYPE_LIST;
    memset(buffer + 1, 0, 4); // from
    memset(buffer + 5, 0, 4); // to

    char buflist[1024] = { 0 };
    int offset = 0;
    for (int i = 0; i < userList.size(); i++) {
        ClientInfo info = userList[i];
        int id = info.id;
        std::string username = info.username.c_str();
        int len = username.length();

        // 4 bytes: id, 4 bytes: size, n bytes: username
        // ... array
        memcpy(buflist + offset, &id, 4);
        memcpy(buflist + offset + 4, &len, 4);
        memcpy(buflist + offset + 8, username.c_str(), len);
        offset += (8 + len);
    }

    memcpy(buffer + 9, &offset, 4);
    memcpy(buffer + 13, buflist, offset);

    if (send(client, buffer, 13 + offset, 0) == SOCKET_ERROR) {
        LOG(ERROR) << "send failed with error: " << WSAGetLastError() << endl;
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
    int size = 4;
    memcpy(buffer + 9, &size, 4);
    
    memcpy(buffer + 13, &uid, 4);

    if (send(client, buffer, 13 + 4, 0) == SOCKET_ERROR) {
        LOG(ERROR) << "send failed with error: " << WSAGetLastError() << endl;
    }
}

void serverForwardMessage(SOCKET socket, int from, int to, char* encrypted_message, int len) {
    char buffer[1024] = { 0 };
    buffer[0] = MESSAGE_TYPE_MESSAGE;
    memcpy(buffer + 1, &from, 4);
    memcpy(buffer + 5, &to, 4);
    memcpy(buffer + 9, &len, 4);

    memcpy(buffer + 13, encrypted_message, len);

    if (send(socket, buffer, 13 + len, 0) == SOCKET_ERROR) {
        LOG(ERROR) << "send failed with error " << WSAGetLastError() << endl;
    }

    LOG(INFO) << "message forwarded to: " << to;
}

BOOL WINAPI console_handler(DWORD cevent)
{
    switch (cevent)
    {
    case  CTRL_C_EVENT:
        LOG(INFO) << "encrypt log file with DES\n";
        encrypt_DES_File("server.log", "server_enc.log");
        exit(0);
        break;
    case  CTRL_BREAK_EVENT:
    case  CTRL_CLOSE_EVENT:
    case  CTRL_LOGOFF_EVENT:
    case  CTRL_SHUTDOWN_EVENT:
    {
        // your code here
        exit(0);
        break;
    }
    default:
        break;
    }
    return  TRUE;
};

void http_server()
{
    Server svr;

    auto ret = svr.set_mount_point("/", "D:\\git\\securechat\\www");
    if (!ret) {
        // The specified base directory doesn't exist...
    }

    svr.set_logger([](const auto& req, const auto& res) {
        LOG(INFO) << "[" << req.method << "] " << req.path << " => " << res.status << endl;
    });

    svr.Post("/register", [](const Request& req, Response& res) {
        if (req.has_header("Content-Length")) {
            auto val = req.get_header_value("Content-Length");
        }

        rapidjson::Document d;
        d.Parse(req.body.c_str());
        assert(d.IsObject());

        LOG(INFO) << "Name: " << d["username"].GetString() << ", gender: " << d["gender"].GetString() 
            << ", age: " << d["age"].GetInt() << ", password: " << d["password"].GetString() << ", email: " << d["email"].GetString() << std::endl;

        int new_uid = db_add_user(d["username"].GetString(), d["gender"].GetString(), d["age"].GetInt(), d["email"].GetString(), d["password"].GetString());
        if (new_uid > 0) {
            rapidjson::Document r;
            r.SetObject();
            r.AddMember("code", 0, r.GetAllocator());
            r.AddMember("msg", "registered!", r.GetAllocator());
            r.AddMember("uid", new_uid, r.GetAllocator());
            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
            r.Accept(writer);

            std::string jsonStr = buffer.GetString();
            res.set_content(jsonStr, "application/json");
        }
        else
            res.set_content("{\"code\":-1,\"msg\":\"failed to register\"}", "application/json");
    });

    svr.listen("localhost", 12345);
}

int db_add_user(const char* username, const char* gender, int age, const char *email, const char* password)
{
    // write db insert
    SQLite::Database db("chat.db3", SQLite::OPEN_READWRITE);

    SQLite::Statement query(db, "INSERT INTO user (name, gender, age, email, password, created_at) VALUES (?, ?, ?, ?, ?, datetime('now', 'localtime'))");
    query.bind(1, username);
    query.bind(2, strcmp(gender, "male") == 0 ? 0 : 1);
    query.bind(3, age);
    query.bind(4, email);
    query.bind(5, password);
    int nb = query.exec();

    SQLite::Statement queryId(db, "SELECT last_insert_rowid();)");
    if (queryId.executeStep()) {
        return 600000 + queryId.getColumn(0).getInt();
    }
    
    return -1;
}

/**
 * @brief Main function to create a server, accept client connections, and start
 * the chat application.
 * @return {int} Exit status of the application.
 */
int main() {
  if (SetConsoleCtrlHandler((PHANDLER_ROUTINE)console_handler, TRUE) == FALSE)
      return -1;

  auto sink_cout = make_shared<AixLog::SinkCout>(AixLog::Severity::info);
  auto sink_file = make_shared<AixLog::SinkFile>(AixLog::Severity::info, "server.log");
  AixLog::Log::init({ sink_cout, sink_file });
  LOG(INFO) << "Hello, World!\n";

  try
  {
      // Open a database file
      SQLite::Database    db("chat.db3", SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE);

      // 0-male, 1-female
      int nb = db.exec("CREATE TABLE IF NOT EXISTS user( \
          id INTEGER PRIMARY KEY AUTOINCREMENT,\
          name TEXT NOT NULL,\
          gender INTEGER DEFAULT 0,\
          age INTEGER NOT NULL,\
          email TEXT UNIQUE,\
          password TEXT NOT NULL,\
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP\
      )");
      std::cout << "create table: " << nb << std::endl;

#ifdef INSERT_DATA
      nb = db.exec("INSERT INTO user (name, gender, age, email, password, created_at) VALUES (\"aa01\", 0, 23, \"aa01@sohu.com\", \"123456\", datetime('now', 'localtime'))");
      std::cout << "insert table: " << nb << std::endl;

      nb = db.exec("INSERT INTO user (name, gender, age, email, password, created_at) VALUES (\"aa02\", 0, 34, \"aa02@sohu.com\", \"123456\", datetime('now', 'localtime'))");
      std::cout << "insert table: " << nb << std::endl;

      nb = db.exec("INSERT INTO user (name, gender, age, email, password, created_at) VALUES (\"bb01\", 1, 46, \"bb01@sohu.com\", \"123456\", datetime('now', 'localtime'))");
      std::cout << "insert table: " << nb << std::endl;
#endif

#ifdef CONDITION_SEARCH
      // Compile a SQL query, containing one parameter (index 1)
      SQLite::Statement query(db, "SELECT * FROM user WHERE name LIKE ?");

      // Bind the integer value 6 to the first parameter of the SQL query
      query.bind(1, "%aa%");
#else
      SQLite::Statement query(db, "SELECT * FROM user");
#endif

      // Loop to execute the query step by step, to get rows of result
      while (query.executeStep())
      {
          // Demonstrate how to get some typed column value
          int         id = 600000 + (int)query.getColumn(0);
          const char* username = query.getColumn(1);
          int gender = query.getColumn(2);
          int age = query.getColumn(3);
          const char* email = query.getColumn(4);
          const char* passwd = query.getColumn(5);
          const char* created_date = query.getColumn(6);

          std::cout << "id: #" << id << ", " << username << ", gender: " << (gender == 0 ? "Male" : "Female") << ", age: " << age << ", email: " << email << ", passwd: " << passwd << ", created at: " << created_date << std::endl;
      }
  }
  catch (std::exception& e)
  {
      std::cout << "exception: " << e.what() << std::endl;
  }

  std::thread t1(http_server);
  t1.detach();

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
