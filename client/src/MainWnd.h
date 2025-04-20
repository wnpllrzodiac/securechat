#ifndef MAIN_WINDOW_H
#define MAIN_WINDOW_H

#include "ui_mainwnd.h"
#include <QMainWindow>
#include <QThread>
#include <winsock2.h>

class QTextEdit;

namespace Ui {
    class MainWnd;
}

struct UserInfo {
    int uid;
    std::string name;
};

class WorkerThread: public QThread {
    Q_OBJECT
public:
    WorkerThread(const SOCKET socket, int uid, const char* password, QObject* parent = nullptr)
        : QThread(parent), m_socket(socket), m_uid(uid), m_password(password) {
    }

    void run() override;

private:
    void sendGetList();
signals:
    void userList(std::vector<UserInfo>);
    void setUserName(const char* username);
    void clearUsers();
    void addUser(int uid, const char* name);
    void removeUser(int uid);
    void failedLogin(std::string reason);
    void appendMessageLog(int form, int to, std::string msg);
   
private:
    SOCKET      m_socket;
    int         m_uid; // 600000
    std::string m_password;
};

class MainWnd : public QMainWindow {
    Q_OBJECT
private:
    Ui::MainWnd ui;

public:
    MainWnd(QWidget* parent = nullptr);
    ~MainWnd();
    QString getNickName() const { return m_nickname; }
    int getUid() const { return m_uid; }
    QString getPassword() const { return m_password; }
    SOCKET getServerSocket() const { return m_server; }
    void setUid(int uid) { m_uid = uid; }

private slots:
    void onUserList(std::vector<UserInfo>);
    void onSetUserName(const char* name);
    void onClearUsers();
    void onAddUser(int uid, const char* username);
    void onRemoveUser(int uid);
    void onFailedLogin(std::string reason);
    void onAppendMessageLog(int from, int to, std::string msg);

private:
    int connectToServer();
    QString getNameFromUID(int uid);
    void sendMessage();
private:
    SOCKET          m_server;
    QTextEdit*      m_logTextEdit;
    QString         m_nickname;
    QString         m_password;
    int             m_uid = -1;
    int             m_to_uid = -1;

    WorkerThread*   m_workerThread;
};
#endif  // MAIN_WINDOW_H