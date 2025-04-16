#include "MainWnd.h"
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "../include/cipher.h"
#include <cstdio>
#include <cstring>
#include <iostream>
#include <thread>

using namespace std;

const char* name_lists[] = {
    "Ash",
    "Skye",
    "Nana"
    "Clover",
    "Kevin",
    "Muriel",
    "Buzz",
    "Baron",
    "August",
    "Mimi",
    "Muse",
    "Jaxon",
    "Titan",
    "Queenie",
    "Roderick",
    "Maxwell",
    "Ralap",
    "Luna",
    "Michelle",
    "Cosima",
    "Sandy",
    "Eric",
    "Amari",
    "Esme",
    "Kennedy",
    "Ah",
    "Herbert",
    "Quinn",
    "Philip",
    "Theodore",
    "William",
    "Alan",
    "Amaya",
    "Erika",
    "Ciel",
    "Cassiel",
    "Jason",
    "Darren",
    "Miya",
    "Marshall",
    "Rhys",
    "Demi",
    "Regina",
    "Cassiopeia",
    "Jo",
    "Derica ",
    "Julian ",
    "Kira",
    "Geri",
    "Frederica",
    "Frederic",
    "Cyan",
    "Gilbert",
    "Angel",
    "tticus",
    "Breaker",
    "Kimi",
    "Dione",
    "airica",
    "Gabrielle",
    "Elijah",
};

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
    MESSAGE_TYPE_GETLIST,
    MESSAGE_TYPE_LIST,
    MESSAGE_TYPE_JOINED,
    MESSAGE_TYPE_LEAVED,
    MESSAGE_TYPE_LOGINRESULT = 20,
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

/**
 * @brief Function to receive data from the server and decrypt it using AES-128.
 * @param {SOCKEt} server The server socket to receive data from.
 */
void clientReceive(MainWnd* ins) {
    SOCKET server = ins->getServerSocket();

    const int MAX_BUFFER_SIZE = 4096;
    char buffer[MAX_BUFFER_SIZE] = { 0 };
    int offset = 0;
    int readed = -1;
    int curr_payload_len = -1;
    while (true) {
        if (offset < 13) {
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
        }

        int msg_type = buffer[0];
        int msg_from = *(int*)(buffer + 1);
        int msg_to = *(int*)(buffer + 5);
        int payload_len = *(int*)(buffer + 9);

        offset += readed;
        if (offset < 13 + payload_len) {
            // not enough data
            curr_payload_len = payload_len;
            std::cout << "not enough data for payload_len: " << offset << ", " << 13 + payload_len << endl;
            continue;
        }

        std::cout << "msg type: " << msg_type << ", msg_len: " << payload_len << ", from: " << msg_from << ", to: " << msg_to << std::endl;

        switch (msg_type) {
        case MESSAGE_TYPE_LOGIN:
            cout << "Login message received" << endl;
            int uid;
            memcpy(&uid, buffer + 13, 4);
            cout << "Your user id is: " << uid << endl;
            ins->setUid(uid);
            break;
        case MESSAGE_TYPE_JOINED:
        case MESSAGE_TYPE_LEAVED:
            {
                char* data = buffer + 13;
                // 4 bytes: id, 4 bytes: size, n bytes: username
                int uid = *(int*)data;
                int name_size = *(int*)(data + 4);
                char name[64] = { 0 };
                memcpy(name, data + 8, name_size);
                cout << "Client: #" << uid << ", " << name << (msg_type == MESSAGE_TYPE_JOINED ? " joined" : " leaved") << endl;

                if (msg_type == MESSAGE_TYPE_JOINED)
                    ins->addUser(uid, name);
                else
                    ins->removeUser(uid);
            }
            break;
        case MESSAGE_TYPE_MESSAGE:
            decrypt_AES(buffer + 13, offset - 13);
            cout << "#" << msg_from << " sent msg to " << msg_to << " :" << buffer + 13;
            ins->appendMessageLog(msg_from, msg_to, buffer + 13);
            break;
        case MESSAGE_TYPE_LIST:
            {
                ins->clearUsers();
                ins->addUser(-1, "all");

                char* data = buffer + 13;
                // 4 bytes: id, 4 bytes: size, n bytes: username
                // ... array
                for (int pos = 0; pos < payload_len;) {
                    int uid = *(int*)(data + pos);
                    int name_size = *(int*)(data + pos + 4);
                    char name[64] = { 0 };
                    memcpy(name, data + pos + 8, name_size);
                    cout << "Client: #" << uid << ", " << name << endl;

                    if (ins->getNickName() != name)
                        ins->addUser(uid, name);

                    pos += (8 + name_size);
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

/**
 * @brief Function to send data to the server after encrypting it using AES-128.
 * @param {SOCKET} server The server socket to send data to.
 */
void clientSend(MainWnd * ins) {
    SOCKET server = ins->getServerSocket();

    char buffer[4096] = { 0 };
    char username[64] = { 0 };
    char msg[4096] = { 0 };

    cout << readme(ins->getNickName().toStdString().c_str());

    strcpy(username, ins->getNickName().toStdString().c_str());
    encrypt_AES(username, strlen(username));

    buffer[0] = MESSAGE_TYPE_LOGIN;
    int invalid_uid = -1;
    memcpy(buffer + 1, &invalid_uid, 4);
    memcpy(buffer + 5, &invalid_uid, 4);
    // fix buffer[1] to buffer[4] with the length of the username
    int size = strlen(username);
    memcpy(buffer + 9, &size, 4);
    memcpy(buffer + 13, username, size);
    int msg_len = 13 + size;
    cout << "to send msg type: " << MESSAGE_TYPE_USERNAME << ", msg_len: " << msg_len << endl;

    if (::send(server, buffer, msg_len, 0) == SOCKET_ERROR) {
        cout << "send failed with error: " << WSAGetLastError() << endl;
        return;
    }

    buffer[0] = MESSAGE_TYPE_GETLIST;
    size = 0;
    memcpy(buffer + 9, &size, 4);
    msg_len = 13; // no payload
    cout << "to send msg type: " << MESSAGE_TYPE_GETLIST << ", msg_len: " << msg_len << endl;
    if (::send(server, buffer, msg_len, 0) == SOCKET_ERROR) {
        cout << "send failed with error: " << WSAGetLastError() << endl;
        return;
    }
    
    cout << "MESSAGE_TYPE_GETLIST sent" << endl;

    return;

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
        int uid = ins->getUid();
        memcpy(buffer + 1, &uid, 4); // from user id
        memcpy(buffer + 5, &to_uid, 4); // to user id
        memcpy(buffer + 9, &size, 4);
        memcpy(buffer + 13, msg, strlen(msg));
        int msg_len = 13 + strlen(msg);

        cout << "to send msg type: " << MESSAGE_TYPE_MESSAGE << ", msg_len: " << msg_len << endl;
        if (::send(server, buffer, msg_len, 0) == SOCKET_ERROR) {
            cout << "send failed with error: " << WSAGetLastError() << endl;
            return;
        }
        if (strcmp(buffer, "exit") == 0) {
            cout << "Thank you for using the application" << endl;
            break;
        }
    }
}

MainWnd::MainWnd(QWidget* parent)
	: QMainWindow(parent)
{
	ui.setupUi(this);

	setWindowTitle("Chat APP");

    srand(time(NULL));
    int index = rand() % (sizeof(name_lists) / sizeof(char *));
    ui.lineEditNickName->setText(name_lists[index]);

    QScrollArea* scrollArea = ui.scrollAreaHistory;
    m_logTextEdit = new QTextEdit();
    m_logTextEdit->setReadOnly(true);

    m_logTextEdit->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
    m_logTextEdit->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

    scrollArea->setWidget(m_logTextEdit);
    scrollArea->setWidgetResizable(true);

    WSADATA WSAData;
    WSAStartup(MAKEWORD(2, 2), &WSAData);

    QObject::connect(ui.pushButtonConnect, &QPushButton::clicked, this, &MainWnd::connectToServer);
    QObject::connect(ui.pushButtonSend, &QPushButton::clicked, this, &MainWnd::sendData);
    QObject::connect(ui.listWidgetClients, &QListWidget::itemClicked, this, [&](QListWidgetItem* item) {
        m_to_uid = item->data(100).toInt();
        cout << "m_to_uid set to: " << m_to_uid << endl;
    });
}

MainWnd::~MainWnd()
{
    closesocket(m_server);

    WSACleanup();
}

void MainWnd::sendData()
{
    QString strMsg = ui.textEditMessage->toPlainText();
    if (strMsg.isEmpty()) {
		return;
	}

	ui.textEditMessage->clear();

	m_logTextEdit->append("You sent: " + strMsg);

    char msg[256] = { 0 };
    strcpy(msg, strMsg.toStdString().c_str());
    encrypt_AES(msg, strlen(msg));

    char buffer[4096] = { 0 };

    memset(buffer, 0, 4096);
    buffer[0] = MESSAGE_TYPE_MESSAGE;
    // fix buffer[1] to buffer[4] with the length of the username
    int size = strlen(msg);
    memcpy(buffer + 1, &m_uid, 4); // from user id
    memcpy(buffer + 5, &m_to_uid, 4); // to user id
    memcpy(buffer + 9, &size, 4);
    memcpy(buffer + 13, msg, strlen(msg));
    int msg_len = 13 + strlen(msg);
    cout << "to send msg type: " << MESSAGE_TYPE_MESSAGE << ", msg_len: " << msg_len << endl;

    if (::send(m_server, buffer, msg_len, 0) == SOCKET_ERROR) {
        cout << "send failed with error: " << WSAGetLastError() << endl;
        return;
    }

}

void MainWnd::addUser(int uid, const char* username)
{
    QListWidgetItem* newItem = new QListWidgetItem(QString(username));
    newItem->setData(100, uid);
    ui.listWidgetClients->addItem(newItem);
}

void MainWnd::removeUser(int uid)
{

}

void MainWnd::appendMessageLog(int from, int to, const char* msg)
{
    QString toDesc = "ALL";
    if (to != -1)
        toDesc = QString("#%1").arg(to);
    if (to == m_uid)
        toDesc = "Me";

    QString str = QString("#%1 say %2 to %3").arg(from).arg(msg).arg(toDesc);
    m_logTextEdit->append(str);
}

void MainWnd::clearUsers()
{
    ui.listWidgetClients->clear();
}

int MainWnd::connectToServer()
{
    m_uid = ui.lineEditNickName->text().toInt();
    m_password = ui.lineEditPassword->text();
    
    SOCKADDR_IN addr;

    if ((m_server = ::socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        cout << "Socket creation failed with error: " << WSAGetLastError() << endl;
        return -1;
    }
    
    std::string ipaddr = ui.lineEditIpAddr->text().toStdString();
    int port = ui.lineEditPort->text().toInt();

    addr.sin_addr.s_addr = inet_addr(ipaddr.c_str());
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (::connect(m_server, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        cout << "Server connection failed with error: " << WSAGetLastError()
            << endl;
        return -1;
    }

    m_logTextEdit->append("Connected to server!");

    cout << "Connected to server!" << endl;
    cout << "Now you can use our live chat application. "
        << " Enter \"exit\" to disconnect" << endl;

    std::thread t1(clientReceive, this);
    std::thread t2(clientSend, this);

    t1.detach();
    t2.detach();

    return 0;
}