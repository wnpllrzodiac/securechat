#ifndef MAIN_WINDOW_H
#define MAIN_WINDOW_H

#include "ui_mainwnd.h"
#include <QMainWindow>

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
private:
    int func();
};
#endif  // MAIN_WINDOW_H