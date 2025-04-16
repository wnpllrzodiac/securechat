#ifndef MAIN_WINDOW_H
#define MAIN_WINDOW_H

#include "ui_mainwnd.h"
#include <QMainWindow>
#include <winsock2.h>

class QTextEdit;

namespace Ui {
    class MainWnd;
}

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
    void clearUsers();
    void addUser(int uid, const char* username);
    void removeUser(int uid);
    void appendMessageLog(int from, int to, const char* msg);
private:
    int connectToServer();
    void sendData();
private:
    SOCKET      m_server;
    QTextEdit*  m_logTextEdit;
    int         m_uid;
    QString     m_nickname;
    QString     m_password;
    int         m_uid = -1;
    int         m_to_uid = -1;
};
#endif  // MAIN_WINDOW_H