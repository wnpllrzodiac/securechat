#include <QApplication>
#include "MainWnd.h"

int main(int argc, char* argv[])
{
    QApplication::setStyle("Fusion"); // fix strange window style
    QApplication app(argc, argv);

    MainWnd w;
    w.setObjectName("MainWnd");
    w.show();

    return app.exec();
}
