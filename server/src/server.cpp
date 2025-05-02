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
#include <curl/curl.h>

using namespace std;
using namespace httplib;

// uid
//server db(1,2,...) <-> send/recv message(600001,60002,...) <-> client(600001,60002,...)

#define UID_BASE 600000

struct ClientInfo {
    int         valid;
    int         id;
    std::string username;
    std::string password;
    std::string email;
    SOCKET      client;

    ClientInfo():valid(-1), id(-1), client(-1) {

    }
};

std::vector<ClientInfo> userList;

enum MESSAGE_TYPE {
    MESSAGE_TYPE_LOGIN = 10,
    MESSAGE_TYPE_GETLIST,
    MESSAGE_TYPE_LIST,
    MESSAGE_TYPE_JOINED,
    MESSAGE_TYPE_LEAVED,
    MESSAGE_TYPE_LOGINRESULT = 20,
    MESSAGE_TYPE_FORGETPASSWORD = 21,
    MESSAGE_TYPE_FORGETPASSWORDRESULT = 22,
    MESSAGE_TYPE_MESSAGE = 30,
    MESSAGE_TYPE_EXIT = 40,
};

enum USEREVENT_TYPE {
    USEREVENT_LOGIN_SUCCESS,
    USEREVENT_LOGIN_INVALID_UID,
    USEREVENT_LOGIN_ALREADY_LOGIN,
    USEREVENT_LOGIN_WRONG_PASSWORD,
    USEREVENT_LOGOUT
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
void serverSendLoginResultMessage(SOCKET client, int success, const char* msg);
void serverForwardMessage(SOCKET socket, int from, int to, char* data, int data_len);
void serverSendForgetPasswordMessage(SOCKET client, unsigned char result, char* message);

int db_add_user(const char* username, const char* gender, int age, const char* email, const char* password);
ClientInfo db_query_user_password(int uid);
int db_add_user_event(int uid, int event);
int db_add_user_msg(int from, int to, const char* msg);

extern "C" {
    char g_key[16] = { 0 };
}

std::string g_mail_password;

std::string getMailPassword() {
    std::ifstream file("mail.txt");
    std::string line;

    if (!file.is_open()) {
      std::cout << "Could not open the file" << std::endl;
      return {};
    }

    if (std::getline(file, line)) {
      file.close();
      return line;
    }

    return {};
}

void generate_random_string(char* str, size_t length = 16) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    size_t charset_size = sizeof(charset) - 1;

    for (size_t i = 0; i < length; i++) {
        str[i] = charset[rand() % charset_size];
    }
}

#define SMTP_MAIL_ADDR          "smtps://smtp.163.com:465"
#define SMTP_MAIL_USERNAME      "shxm.ma@163.com"

#define FROM_ADDR    "<shxm.ma@163.com>"
#define TO_ADDR      "<wnpllr@gmail.com>"
#define CC_ADDR      "<info@example.org>"

#define FROM_MAIL "Sender Person " FROM_ADDR
#define TO_MAIL   "A Receiver " TO_ADDR
#define CC_MAIL   "John CC Smith " CC_ADDR

static const char* payload_text =
"Date: Mon, 29 Nov 2010 21:54:29 +1100\r\n"
"To: " TO_MAIL "\r\n"
"From: " FROM_MAIL "\r\n"
"Cc: " CC_MAIL "\r\n"
"Message-ID: <dcd7cb36-11db-487a-9f3a-e652a9458efd@"
"rfcpedant.example.org>\r\n"
"Subject: SMTP example message\r\n"
"\r\n" /* empty line to divide headers from body, see RFC 5322 */
"The body of the message starts here.\r\n"
"\r\n"
"It could be a lot of lines, could be MIME encoded, whatever.\r\n"
"Your password is $PASSWORD.\r\n";

std::string payload_text_changed;

struct upload_status {
    size_t bytes_read;
    std::string password;
};

static size_t payload_source(char* ptr, size_t size, size_t nmemb, void* userp)
{
    struct upload_status* upload_ctx = (struct upload_status*)userp;
    const char* data;
    size_t room = size * nmemb;

    if ((size == 0) || (nmemb == 0) || ((size * nmemb) < 1)) {
        return 0;
    }

    const char* txt = payload_text_changed.c_str();
    data = &txt[upload_ctx->bytes_read];

    if (data) {
        size_t len = strlen(data);
        if (room < len)
            len = room;
        memcpy(ptr, data, len);
        upload_ctx->bytes_read += len;

        return len;
    }

    return 0;
}

static int send_mail(const char* to_addr, const char* password)
{
    if (g_mail_password.empty()) {
        cout << "smtp mail password not set" << endl;
        return -1;
    }

    std::string string(payload_text);
    payload_text_changed = std::regex_replace(string, std::regex("\\$PASSWORD"), password);

    CURL* curl;
    CURLcode res = CURLE_OK;
    struct curl_slist* recipients = NULL;
    struct upload_status upload_ctx = { 0 };

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, SMTP_MAIL_ADDR);
        curl_easy_setopt(curl, CURLOPT_USERNAME, SMTP_MAIL_USERNAME);
        curl_easy_setopt(curl, CURLOPT_PASSWORD, g_mail_password.c_str());

        curl_easy_setopt(curl, CURLOPT_MAIL_FROM, FROM_ADDR);

        struct curl_slist* recipients = nullptr;
        recipients = curl_slist_append(recipients, to_addr);
        //recipients = curl_slist_append(recipients, CC_ADDR);
        curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

        curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);

        curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_source);
        curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
        }
        else {
            std::cout << "Email sent successfully!" << std::endl;
        }

        curl_slist_free_all(recipients);
        curl_easy_cleanup(curl);
    }
    return 0;
}

/**
 * @brief Function to receive data from the client, decrypt it using AES-128,
 * and display it.
 * @param {SOCKET} client The client socket to receive data from.
 */
void serverReceive(SOCKET client) {
    const int MAX_BUFFER_SIZE = 4096;
    char buffer[MAX_BUFFER_SIZE] = {0};
    char encrypted_msg[MAX_BUFFER_SIZE] = { 0 };
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

                if (leaved_uid != -1) {
                    ClientInfo ci = db_query_user_password(leaved_uid - UID_BASE);
                    if (ci.valid == 1) {
                        db_add_user_event(leaved_uid - UID_BASE, USEREVENT_LOGOUT);
                        serverSendLeavedMessage(leaved_uid);
                    }
                }

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

        memset(encrypted_msg, 0, MAX_BUFFER_SIZE);

        int uid = -1;
        unsigned char is_enc = 0;
        switch (msg_type) {
        case MESSAGE_TYPE_LOGIN:
            // 4 bytes uid, password
        {
            memcpy(&uid, buffer + 13, 4);
            LOG(INFO) << "Client login() uid: " << uid << endl;

            char password[64] = { 0 };
            memcpy(password, buffer + 13 + 4, payload_len - 4);
            LOG(INFO) << "Client login() password: " << password << endl;

            int already_login = 0;
            for (auto info : userList) {
                if (info.id == uid) {
                    already_login = 1;

                    LOG(INFO) << "Client #" << uid << " already logined\n";
                    break;
                }
            }

            if (!already_login) {
                // lookup password
                ClientInfo info = db_query_user_password(uid - UID_BASE);

                if (info.valid == 1 && info.password == password) {
                    db_add_user_event(info.id, USEREVENT_LOGIN_SUCCESS);

                    info.id += UID_BASE;
                    info.client = client;
                    userList.push_back(info);
                    LOG(INFO) << "Client #" << uid << " added to list\n";

                    serverSendLoginResultMessage(client, 0, info.username.c_str());

                    serverSendJoinedMessage(uid, info.username.c_str());
                }
                else {
                    db_add_user_event(uid - UID_BASE, USEREVENT_LOGIN_WRONG_PASSWORD);
                    serverSendLoginResultMessage(client, -1, "invalid uid or password");
                }
            }
            else{
                db_add_user_event(uid - UID_BASE, USEREVENT_LOGIN_ALREADY_LOGIN);
                serverSendLoginResultMessage(client, -1, "this uid already logined");
            }
        }
           
            break;
        case MESSAGE_TYPE_MESSAGE:
        {
            // 1 byte is_enc, bytes message
            memcpy(&is_enc, buffer + 13, 1);
            memcpy(encrypted_msg, buffer + 13 + 1, payload_len - 1);
            LOG(INFO) << "Client msg(encrypted): " << encrypted_msg << ", to: " << msg_to << "\n";
            printf("is_enc: %d\n", is_enc);

            int user_from = msg_from;
            int user_to = msg_to;
            if (user_from != -1)
                user_from -= UID_BASE;
            if (user_to != -1)
                user_to -= UID_BASE;

            char decrypted_msg[MAX_BUFFER_SIZE] = { 0 };
            if (is_enc) {
                int outlen = 0;
                decrypt_AES((unsigned char*)encrypted_msg, payload_len - 1, (unsigned char*)decrypted_msg, &outlen);
                decrypted_msg[outlen] = 0x0;
                db_add_user_msg(user_from, user_to, decrypted_msg);
            }
            else {
                db_add_user_msg(user_from, user_to, encrypted_msg);
            }

            if (msg_to == -1) {
                // broadcast
                LOG(INFO) << "broadcast msg: " << (is_enc ? decrypted_msg : encrypted_msg) << "\n";

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
        }
            break;
        case MESSAGE_TYPE_GETLIST:
            serverSendUserList(client);
            break;
        case MESSAGE_TYPE_EXIT:
            LOG(INFO) << "Client Disconnected.";
            break;
        case MESSAGE_TYPE_FORGETPASSWORD:
        {
            // 4 bytes uid, bytes email
            memcpy(&uid, buffer + 13, 4);
            LOG(INFO) << "Client forgetpassword() uid: " << uid << endl;

            char email[64] = { 0 };
            memcpy(email, buffer + 13 + 4, payload_len - 4);
            LOG(INFO) << "Client forgetpassword() email: " << email << endl;

            ClientInfo info = db_query_user_password(uid - UID_BASE);
            if (info.valid == 1 && stricmp(email, info.email.c_str()) == 0) {
                send_mail(email, info.password.c_str());
                serverSendForgetPasswordMessage(client, 0, "mail sent.");
            }
            else {
                LOG(ERROR) << "invalid uid or password: is_valid: " << info.valid << ", " << info.password << endl;
                serverSendForgetPasswordMessage(client, 1, "uid and email mismatch");
            }

        }
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

void serverSendForgetPasswordMessage(SOCKET client, unsigned char result, char *message)
{
    char buffer[1024] = { 0 };
    buffer[0] = MESSAGE_TYPE_FORGETPASSWORDRESULT;
    int invalid_id = -1;
    memcpy(buffer + 1, &invalid_id, 4); // from
    memcpy(buffer + 5, &invalid_id, 4); // to

    int len = strlen(message);

    int payload_len = len + 1;
    memcpy(buffer + 9, &payload_len, 4);

    // 1 byte: result, bytes: message

    memcpy(buffer + 13, &result, 1);
    memcpy(buffer + 13 + 1, message, len);

    if (send(client, buffer, 13 + payload_len, 0) == SOCKET_ERROR) {
        LOG(ERROR) << "send failed with error: " << WSAGetLastError() << endl;
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
    LOG(INFO) << "serverSendLeavedMessage()" << "uid: " << uid << "\n";

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
        std::string username = info.username.c_str();
        int len = username.length();

        // 4 bytes: id, 4 bytes: size, n bytes: username
        // ... array
        memcpy(buflist + offset, &info.id, 4);
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
void serverSendLoginResultMessage(SOCKET client, int success, const char* msg) {
    char buffer[1024] = {0};
    buffer[0] = MESSAGE_TYPE_LOGINRESULT;
    memset(buffer + 1, 0, 4);
    memset(buffer + 5, 0, 4);
    int payload_size = 4 + 16 + strlen(msg);
    memcpy(buffer + 9, &payload_size, 4);
    
    // payload
    // 4 bytes result, 16 bytes key, N bytes message
    memcpy(buffer + 13, &success, 4);
    memcpy(buffer + 13 + 4, g_key, 16);
    memcpy(buffer + 13 + 4 + 16, msg, strlen(msg));

    if (send(client, buffer, 13 + payload_size, 0) == SOCKET_ERROR) {
        LOG(ERROR) << "send failed with error: " << WSAGetLastError() << endl;
    }
}

void serverForwardMessage(SOCKET socket, int from, int to, char* data, int data_len) {
    char buffer[1024] = { 0 };
    buffer[0] = MESSAGE_TYPE_MESSAGE;
    memcpy(buffer + 1, &from, 4);
    memcpy(buffer + 5, &to, 4);
    memcpy(buffer + 9, &data_len, 4);
    memcpy(buffer + 13, data, data_len);

    if (send(socket, buffer, 13 + data_len, 0) == SOCKET_ERROR) {
        LOG(ERROR) << "send failed with error " << WSAGetLastError() << endl;
    }

    LOG(INFO) << "message forwarded to: " << to << endl;
}

BOOL WINAPI console_handler(DWORD cevent)
{
    switch (cevent)
    {
    case  CTRL_C_EVENT:
        LOG(INFO) << "encrypt log file with DES\n";
        //encrypt_DES_File("server.log", "server_enc.log");
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

#ifdef _DEBUG
    auto ret = svr.set_mount_point("/", "D:\\download\\code\\securechat\\www");
#else
    auto ret = svr.set_mount_point("/", "./www");
#endif
    if (!ret) {
        // The specified base directory doesn't exist...
    }

    svr.set_logger([](const auto& req, const auto& res) {
        LOG(INFO) << "[" << req.method << "] " << req.path << " => " << res.status << endl;
    });

    svr.Get("/getlog", [](const Request& req, Response& res) {
    /*
    [
        {
            "level": "INFO",
            "message": "系统启动成功",
            "timestamp": "2025-04-19 06:30:00",
            "project": "系统服务"
        },
        {
            "level": "WARN",
            "message": "内存使用率接近上限",
            "timestamp": "2025-04-19 06:32:00",
            "project": "性能监控"
        }
    ]
    */
        try {
            rapidjson::Document r;
            r.SetArray();
            rapidjson::Document::AllocatorType& allocator = r.GetAllocator();

            SQLite::Database db("chat.db3");

            SQLite::Statement query(db, "SELECT level,message,added_at FROM log");

            while (query.executeStep()) {
                int level = query.getColumn(0);
                const char* msg = query.getColumn(1);
                const char* date = query.getColumn(2);
                const char* level_txt = "info";
                if (level == 2)
                    level_txt = "info";
                else if (level == 4)
                    level_txt = "warn";
                else if (level == 5)
                    level_txt = "error";
                rapidjson::Value member(rapidjson::kObjectType);
                member.AddMember("level", rapidjson::Value(level_txt, allocator).Move(), allocator);
                member.AddMember("message", rapidjson::Value(msg, allocator).Move(), allocator);
                member.AddMember("added_at", rapidjson::Value(date, allocator).Move(), allocator);
                r.PushBack(member, allocator);
            }

            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
            r.Accept(writer);

            std::string jsonStr = buffer.GetString();
            res.set_content(jsonStr, "application/json");
            return;
        }
        catch (std::exception& e)
        {
            std::cout << "exception: " << e.what() << std::endl;
        }

        res.set_content("{\"code\":-1,\"msg\":\"error\"}", "application/json");
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
            new_uid += UID_BASE;

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

ClientInfo db_query_user_password(int uid)
{
    ClientInfo info;

    try {
        SQLite::Database db("chat.db3");

        SQLite::Statement query(db, "SELECT name,password,email FROM user WHERE id = ?");
        query.bind(1, uid);

        if (query.executeStep()) {
            info.valid = 1;
            const char* name = query.getColumn(0);
            const char* password = query.getColumn(1);
            const char* email = query.getColumn(2);
            info.id = uid;
            info.username = name;
            info.password = password;
            info.email = email;
        }
    }
    catch (std::exception& e)
    {
        std::cout << "exception: " << e.what() << std::endl;
    }

    return info;
}

void db_add_log(int level, const char* msg)
{
    // write db insert
    SQLite::Database db("chat.db3", SQLite::OPEN_READWRITE);

    SQLite::Statement query(db, "INSERT INTO log (level, message, added_at) VALUES (?, ?, datetime('now', 'localtime'))");
    query.bind(1, level);
    query.bind(2, msg);
    int nb = query.exec();
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

    SQLite::Statement queryId(db, "SELECT last_insert_rowid();");
    if (queryId.executeStep()) {
        return queryId.getColumn(0).getInt();
    }
    
    return -1;
}

int db_create_tables()
{
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
        std::cout << "create table user: " << nb << std::endl;

        // log level: 2-info, 4-warning, 5-error
        nb = db.exec("CREATE TABLE IF NOT EXISTS log( \
            id INTEGER PRIMARY KEY AUTOINCREMENT,\
            level INTEGER NOT NULL,\
            message TEXT NOT NULL,\
            added_at DATETIME DEFAULT CURRENT_TIMESTAMP\
        )");
        std::cout << "create table log: " << nb << std::endl;

        // event: 10-login(succesfully), 11-login(failed with invalid uid), 12-login(failed with already logined), 13-login(failed with mismatch username/passwd)
        // event: 20-logout
        nb = db.exec("CREATE TABLE IF NOT EXISTS userevent( \
            id INTEGER PRIMARY KEY AUTOINCREMENT,\
            uid INTEGER NOT NULL,\
            event INTEGER NOT NULL,\
            event_at DATETIME DEFAULT CURRENT_TIMESTAMP\
        )");
        std::cout << "create table userevent: " << nb << std::endl;

        nb = db.exec("CREATE TABLE IF NOT EXISTS usermessage( \
            id INTEGER PRIMARY KEY AUTOINCREMENT,\
            from_user INTEGER NOT NULL,\
            to_user INTEGER NOT NULL,\
            message TEXT NOT NULL,\
            added_at DATETIME DEFAULT CURRENT_TIMESTAMP\
        )");
        std::cout << "create table usermessage: " << nb << std::endl;

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
            int         id = UID_BASE + (int)query.getColumn(0);
            const char* username = query.getColumn(1);
            int gender = query.getColumn(2);
            int age = query.getColumn(3);
            const char* email = query.getColumn(4);
            const char* passwd = query.getColumn(5);
            const char* created_date = query.getColumn(6);

            std::cout << "id: #" << id << ", " << username << ", gender: " << (gender == 0 ? "Male" : "Female") << ", age: " << age << ", email: " << email << ", passwd: " << passwd << ", created at: " << created_date << std::endl;
        }

#ifdef DUMP_LOG
        SQLite::Statement queryLog(db, "SELECT level,message,added_at FROM log ORDER BY added_at LIMIT 30");

        while (queryLog.executeStep()) {
            int level = queryLog.getColumn(0);
            const char* msg = queryLog.getColumn(1);
            const char* date = queryLog.getColumn(2);
            std::cout << "[" << level << "] " << msg << " at " << date << std::endl;
        }
#endif
    }
    catch (std::exception& e)
    {
        std::cout << "exception: " << e.what() << std::endl;
        return -1;
    }

    return 0;
}

int db_add_user_event(int uid, int event)
{
    SQLite::Database db("chat.db3", SQLite::OPEN_READWRITE);

    SQLite::Statement query(db, "INSERT INTO userevent (uid, event, event_at) VALUES (?, ?, datetime('now', 'localtime'))");
    query.bind(1, uid);
    query.bind(2, event);
    int nb = query.exec();

    return 0;
}

std::string Unicode2Utf8(const std::wstring& widestring) {
    using namespace std;
    int utf8size = ::WideCharToMultiByte(CP_UTF8, 0, widestring.c_str(), -1, NULL, 0, NULL, NULL);
    if (utf8size == 0)
    {
        throw std::exception("Error in conversion.");
    }
    std::vector<char> resultstring(utf8size);
    int convresult = ::WideCharToMultiByte(CP_UTF8, 0, widestring.c_str(), -1, &resultstring[0], utf8size, NULL, NULL);
    if (convresult != utf8size)
    {
        throw std::exception("La falla!");
    }
    return std::string(&resultstring[0]);
}

std::wstring Acsi2WideByte(std::string& strascii) {
    using namespace std;
    int widesize = MultiByteToWideChar(CP_ACP, 0, (char*)strascii.c_str(), -1, NULL, 0);
    if (widesize == ERROR_NO_UNICODE_TRANSLATION)
    {
        throw std::exception("Invalid UTF-8 sequence.");
    }
    if (widesize == 0)
    {
        throw std::exception("Error in conversion.");
    }
    std::vector<wchar_t> resultstring(widesize);
    int convresult = MultiByteToWideChar(CP_ACP, 0, (char*)strascii.c_str(), -1, &resultstring[0], widesize);
    if (convresult != widesize)
    {
        throw std::exception("La falla!");
    }
    return std::wstring(&resultstring[0]);
}

int db_add_user_msg(int from, int to, const char* msg)
{
    std::string strAsciiCode = msg;
    wstring wstr = Acsi2WideByte(strAsciiCode);
    //最后把 unicode 转为 utf8 
    std::string finalStr = Unicode2Utf8(wstr);

    SQLite::Database db("chat.db3", SQLite::OPEN_READWRITE);

    SQLite::Statement query(db, "INSERT INTO usermessage (from_user, to_user, message, added_at) VALUES (?, ?, ?, datetime('now', 'localtime'))");
    query.bind(1, from);
    query.bind(2, to);
    query.bind(3, finalStr.c_str());
    int nb = query.exec();

    return 0;
}

/**
 * @brief Main function to create a server, accept client connections, and start
 * the chat application.
 * @return {int} Exit status of the application.
 */
int main()
{
    if (SetConsoleCtrlHandler((PHANDLER_ROUTINE)console_handler, TRUE) == FALSE) {
        printf("failed to set ctrl handler\n");
        return -1;
    }

    std::string mypassword = getMailPassword();
    if (!mypassword.empty()) {
        printf("mail password: %s\n", mypassword.c_str());
        g_mail_password = mypassword;
    }

    generate_random_string(g_key);
    char str_key[17] = { 0 };
    memcpy(str_key, g_key, 16);
    std::cout << "key: " << str_key << std::endl;

    if (db_create_tables() != 0) {
        printf("failed to init db\n");
        return -1;
    }

    auto sink_cout = make_shared<AixLog::SinkCout>(AixLog::Severity::info);
    auto sink_file = make_shared<AixLog::SinkFile>(AixLog::Severity::info, "server.log");
    auto sink_func = make_shared<AixLog::SinkCallback>(AixLog::Severity::info,
        [](const AixLog::Metadata& metadata, const std::string& message)
        {
            db_add_log((int)metadata.severity, message.c_str());
        }
    );
    AixLog::Log::init({ sink_cout, sink_file, sink_func });
    LOG(INFO) << "Hello, World!\n";

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
