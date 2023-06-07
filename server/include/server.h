#ifndef SERVER_H
#define SERVER_H

#include <winsock2.h>

DWORD WINAPI serverReceive(LPVOID lpParam);

DWORD WINAPI serverSend(LPVOID lpParam);

#endif // SERVER_H
