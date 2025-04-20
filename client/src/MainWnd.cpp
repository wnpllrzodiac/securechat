#include "MainWnd.h"
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "../include/cipher.h"
#include <cstdio>
#include <cstring>
#include <iostream>
#include <thread>
#include <QMessageBox>

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
void WorkerThread::run() {
    const int MAX_BUFFER_SIZE = 4096;
    char buffer[MAX_BUFFER_SIZE] = { 0 };
    int offset = 0;
    int readed = -1;
    int curr_payload_len = -1;

    char msg[4096] = { 0 };

    buffer[0] = MESSAGE_TYPE_LOGIN;
    int invalid_uid = -1;
    memcpy(buffer + 1, &invalid_uid, 4);
    memcpy(buffer + 5, &invalid_uid, 4);
    // fix buffer[1] to buffer[4] with the length of the username

    // 4 bytes uid, password
    int payload_size = 4 + m_password.length();
    memcpy(buffer + 9, &payload_size, 4);
    memcpy(buffer + 13, &m_uid, 4);
    memcpy(buffer + 13 + 4, m_password.c_str(), m_password.length());
    int msg_len = 13 + payload_size;
    cout << "to send msg type: " << MESSAGE_TYPE_LOGIN << ", msg_len: " << msg_len << endl;

    if (::send(m_socket, buffer, msg_len, 0) == SOCKET_ERROR) {
        cout << "send failed with error: " << WSAGetLastError() << endl;
        return;
    }

    while (true) {
        if (offset < 13) {
            int toread = MAX_BUFFER_SIZE - offset;
            if (curr_payload_len > 0) {
                toread = curr_payload_len - (offset - 13);
            }

            if ((readed = recv(m_socket, buffer + offset, toread, 0)) == SOCKET_ERROR) {
                cout << "recv function failed with error " << WSAGetLastError() << endl;
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

        if (offset < 13 + payload_len) {
            // not enough data
            curr_payload_len = payload_len;
            std::cout << "not enough data for payload_len: " << offset << ", " << 13 + payload_len << endl;
            continue;
        }

        std::cout << "msg type: " << msg_type << ", msg_len: " << payload_len << ", from: " << msg_from << ", to: " << msg_to << std::endl;

        switch (msg_type) {
        case MESSAGE_TYPE_LOGINRESULT:
            cout << "Login result message received" << endl;

            {
                // 4 bytes result, bytes message
                int result;
                char message[256] = { 0 };
                memcpy(&result, buffer + 13, 4);
                memcpy(message, buffer + 13 + 4, payload_len - 4);

                if (result == 0) {
                    std::cout << "login result: succesful" << std::endl;
                    emit setUserName(message);

                    sendGetList();
                }
                else {
                    std::cout << "login result: failed" << std::endl;
                    emit failedLogin(message);
                }
            }
            
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

                if (msg_type == MESSAGE_TYPE_JOINED) {
                    emit addUser(uid, name);
                }
                else {
                    emit removeUser(uid);
                }
            }
            break;
        case MESSAGE_TYPE_MESSAGE:
            {
                // 1 byte is_enc, bytes message
                unsigned char is_enc = 0;
                memcpy(&is_enc, buffer + 13, 1);
                if (is_enc)
                    decrypt_AES(buffer + 13 + 1, offset - 13 - 1);
                cout << "#" << msg_from << " sent msg to " << msg_to << " :" << buffer + 13 + 1 << endl;
                std::string msg = buffer + 13 + 1;
                emit appendMessageLog(msg_from, msg_to, msg);
             }
            
            break;
        case MESSAGE_TYPE_LIST:
            {
                cout << "MESSAGE_TYPE_LIST" << endl;

                emit clearUsers();
                emit addUser(-1, "all");

                std::vector<UserInfo> list;

                char* data = buffer + 13;
                // 4 bytes: id, 4 bytes: size, n bytes: username
                // ... array
                for (int pos = 0; pos < payload_len;) {
                    int uid = *(int*)(data + pos);
                    int name_size = *(int*)(data + pos + 4);
                    char name[64] = { 0 };
                    memcpy(name, data + pos + 8, name_size);
                    cout << "add Client: #" << uid << ", " << name << "to user list" << endl;

                    //if (ins->getUid() != uid)
                     //   ins->addUser(uid, name);
                    UserInfo info;
                    info.uid = uid;
                    info.name = name;
                    list.push_back(info);

                    pos += (8 + name_size);
                }

                emit userList(list);
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

void WorkerThread::sendGetList()
{
    char buffer[4096] = { 0 };

    buffer[0] = MESSAGE_TYPE_GETLIST;
    int size = 0;
    memcpy(buffer + 9, &size, 4);
    int msg_len = 13; // no payload
    cout << "to send msg type: " << MESSAGE_TYPE_GETLIST << ", msg_len: " << msg_len << endl;
    if (::send(m_socket, buffer, msg_len, 0) == SOCKET_ERROR) {
        cout << "send failed with error: " << WSAGetLastError() << endl;
        return;
    }

    cout << "MESSAGE_TYPE_GETLIST sent" << endl;
}

void MainWnd::onUserList(std::vector<UserInfo> list)
{
    for (auto info : list) {
        if (info.uid != m_uid)
            onAddUser(info.uid, info.name.c_str());
    }
}

/**
 * @brief Function to send data to the server after encrypting it using AES-128.
 * @param {SOCKET} server The server socket to send data to.
 */
void clientSend(MainWnd * ins) {
    SOCKET server = ins->getServerSocket();

    char buffer[4096] = { 0 };
    char password[64] = { 0 };
    char msg[4096] = { 0 };

    strcpy(password, ins->getPassword().toStdString().c_str());

    int uid = ins->getUid();

    buffer[0] = MESSAGE_TYPE_LOGIN;
    int invalid_uid = -1;
    memcpy(buffer + 1, &invalid_uid, 4);
    memcpy(buffer + 5, &invalid_uid, 4);
    // fix buffer[1] to buffer[4] with the length of the username

    // 4 bytes uid, password
    int payload_size = 4 + strlen(password);
    memcpy(buffer + 9, &payload_size, 4);
    memcpy(buffer + 13, &uid, 4);
    memcpy(buffer + 13 + 4, password, strlen(password));
    int msg_len = 13 + payload_size;
    cout << "to send msg type: " << MESSAGE_TYPE_LOGIN << ", msg_len: " << msg_len << endl;

    if (::send(server, buffer, msg_len, 0) == SOCKET_ERROR) {
        cout << "send failed with error: " << WSAGetLastError() << endl;
        return;
    }
}

MainWnd::MainWnd(QWidget* parent)
	: QMainWindow(parent)
{
	ui.setupUi(this);

	setWindowTitle("Chat APP");

    srand(time(NULL));
    //int index = rand() % (sizeof(name_lists) / sizeof(char *));
    //ui.lineEditNickName->setText(name_lists[index]);

    QScrollArea* scrollArea = ui.scrollAreaHistory;
    m_logTextEdit = new QTextEdit();
    m_logTextEdit->setReadOnly(true);

    m_logTextEdit->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
    m_logTextEdit->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

    scrollArea->setWidget(m_logTextEdit);
    scrollArea->setWidgetResizable(true);

    WSADATA WSAData;
    WSAStartup(MAKEWORD(2, 2), &WSAData);

    ui.pushButtonSend->setEnabled(false);

    QObject::connect(ui.pushButtonConnect, &QPushButton::clicked, this, &MainWnd::connectToServer);
    QObject::connect(ui.pushButtonSend, &QPushButton::clicked, this, &MainWnd::sendMessage);
    QObject::connect(ui.listWidgetClients, &QListWidget::itemClicked, this, [&](QListWidgetItem* item) {
        m_to_uid = item->data(Qt::UserRole).toInt();
        cout << "m_to_uid set to: " << m_to_uid << endl;
    });
}

MainWnd::~MainWnd()
{
    closesocket(m_server);

    WSACleanup();
}

QString MainWnd::getNameFromUID(int uid)
{
    for (int i = 0;i < ui.listWidgetClients->count();i++) {
        QListWidgetItem* item = ui.listWidgetClients->item(i);
        if (item->data(Qt::UserRole).toInt() == uid) {
            return item->text();
        }
    }

    return "";
}

void MainWnd::sendMessage()
{
    QString strMsg = ui.textEditMessage->toPlainText();
    if (strMsg.isEmpty()) {
		return;
	}

	m_logTextEdit->append("You sent: " + strMsg);

    unsigned char is_enc = 1;

    char msg[256] = { 0 };

    QByteArray byteArray = strMsg.toLocal8Bit();
    const char* output = byteArray.constData();
    printf("input msg: %s\n", output);

    strcpy(msg, byteArray.constData());
    char encryped_msg[256] = { 0 };
    memcpy(encryped_msg, msg, 256);
    if (is_enc)
        encrypt_AES(encryped_msg, strlen(msg));

    char buffer[4096] = { 0 };

    memset(buffer, 0, 4096);

    buffer[0] = MESSAGE_TYPE_MESSAGE;
    // fix buffer[1] to buffer[4] with the length of the username
    int size = 1 + strlen(encryped_msg);
    memcpy(buffer + 1, &m_uid, 4); // from user id
    memcpy(buffer + 5, &m_to_uid, 4); // to user id
    memcpy(buffer + 9, &size, 4);

    // 1 byte is_enc, bytes message
    memcpy(buffer + 13, &is_enc, 1);
    memcpy(buffer + 13 + 1, encryped_msg, strlen(encryped_msg));
    int msg_len = 13 + 1 + strlen(encryped_msg);
    cout << "to send msg type: " << MESSAGE_TYPE_MESSAGE << ", msg_len: " << msg_len << ", plain msg: " << msg << endl;

    if (::send(m_server, buffer, msg_len, 0) == SOCKET_ERROR) {
        cout << "send failed with error: " << WSAGetLastError() << endl;
        QMessageBox::warning(nullptr, "error", "failed to send message");
        return;
    }

    ui.textEditMessage->clear();
}

void MainWnd::onSetUserName(const char* name)
{
    ui.label_UserName->setText(QString("My username is: %1").arg(name));
}

void MainWnd::onAddUser(int uid, const char* username)
{
    QListWidgetItem* newItem = new QListWidgetItem(QString(username));
    newItem->setData(Qt::UserRole, uid);
    ui.listWidgetClients->addItem(newItem);
    qDebug() << "onAddUser() add uid: " << uid << "to list";

#ifdef _DEBUG
    if (ui.listWidgetClients->count() > 0)
#else
    if (ui.listWidgetClients->count() > 1)
#endif
        ui.pushButtonSend->setEnabled(true);
}

void MainWnd::onRemoveUser(int uid)
{
    qDebug() << "onRemoveUser(): " << uid;
    for (int i = 0;i < ui.listWidgetClients->count();i++) {
        QListWidgetItem* item = ui.listWidgetClients->item(i);
        if (item->data(Qt::UserRole).toInt() == uid) {
            qDebug() << "onRemoveUser() remove uid: " << uid << "from list";
            delete item;
            break;
        }
    }
    
    if (ui.listWidgetClients->count() <= 1)
        ui.pushButtonSend->setEnabled(false);
}

void MainWnd::onFailedLogin(std::string reason)
{
    QMessageBox::warning(nullptr, "login", reason.c_str());
}

void MainWnd::onAppendMessageLog(int from, int to, std::string msg)
{
    QString toDesc = "ALL";
    if (to != -1)
        toDesc = "Me";

    QString fromDesc = QString("# %1").arg(from);
    if (from != -1 && !getNameFromUID(from).isEmpty())
        fromDesc = getNameFromUID(from);

    QString strMsg = QString::fromLocal8Bit(msg.c_str());
    QString str = QString("%1 say %2 to %3").arg(fromDesc).arg(strMsg).arg(toDesc);
    m_logTextEdit->append(str);
}

void MainWnd::onClearUsers()
{
    ui.listWidgetClients->clear();
}

int MainWnd::connectToServer()
{
    m_uid = ui.lineEditUID->text().toInt();
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

    m_workerThread = new WorkerThread(m_server, m_uid, m_password.toStdString().c_str());

    connect(m_workerThread, &WorkerThread::userList, this, &MainWnd::onUserList);
    connect(m_workerThread, &WorkerThread::setUserName, this, &MainWnd::onSetUserName);
    connect(m_workerThread, &WorkerThread::clearUsers, this, &MainWnd::onClearUsers);
    connect(m_workerThread, &WorkerThread::addUser, this, &MainWnd::onAddUser);
    connect(m_workerThread, &WorkerThread::removeUser, this, &MainWnd::onRemoveUser);
    connect(m_workerThread, &WorkerThread::failedLogin, this, &MainWnd::onFailedLogin);
    connect(m_workerThread, &WorkerThread::appendMessageLog, this, &MainWnd::onAppendMessageLog);

    m_workerThread->start();

    return 0;
}