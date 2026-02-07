#include <windows.h>
#include <stdio.h>
#include "cd.h"
#include "../Command.h"
#include "../Utils.h"

BOOL executeCd(PParser arguments)
{
    // 1. Get Task UUID
    SIZE_T uuidLen = 0;
    PBYTE uuidBytes = ParserGetBytes(arguments, &uuidLen);
    
    if (!uuidBytes) 
    {
        LOG("[-] executeCd: Failed to get UUID");
        return FALSE;
    }

    PCHAR taskUuid = (PCHAR)LocalAlloc(LPTR, uuidLen + 1);
    if (!taskUuid) { LocalFree(uuidBytes); return FALSE; }
    memcpy(taskUuid, uuidBytes, uuidLen);
    taskUuid[uuidLen] = '\0';
    LocalFree(uuidBytes);
    
    // 2. Num Args
    UINT32 nbArg = ParserGetInt32(arguments);
    (void)nbArg;

    // 3. Path
    SIZE_T cmdLen = 0;
    PBYTE cmdBytes = ParserGetBytes(arguments, &cmdLen);

    PPackage responseTask = PackageCreate();
    PackageAddByte(responseTask, POST_RESPONSE);
    PackageAddBytes(responseTask, (PBYTE)taskUuid, uuidLen);
    PPackage output = PackageCreate();

    if (cmdBytes)
    {
        PCHAR path = (PCHAR)LocalAlloc(LPTR, cmdLen + 1);
        if (path)
        {
            memcpy(path, cmdBytes, cmdLen);
            path[cmdLen] = '\0';

            LOG("[*] Changing directory to: %s", path);
            
            if (SetCurrentDirectory(path))
            {
                // Success! Let's tell the boss where we are now.
                CHAR currentDir[MAX_PATH];
                if (GetCurrentDirectory(MAX_PATH, currentDir))
                {
                    char* msg = "Changed directory to: ";
                    PackageAddBytesRaw(output, (PBYTE)msg, strlen(msg));
                    PackageAddBytesRaw(output, (PBYTE)currentDir, strlen(currentDir));
                }
                else
                {
                    char* msg = "Changed directory (failed to get new CWD)";
                    PackageAddBytesRaw(output, (PBYTE)msg, strlen(msg));
                }
            }
            else
            {
                 // Failed
                char* err = "Failed to change directory";
                PackageAddBytesRaw(output, (PBYTE)err, strlen(err));
            }
            LocalFree(path);
        }
        LocalFree(cmdBytes);
    }
    else
    {
         char* err = "Missing path argument";
         PackageAddBytesRaw(output, (PBYTE)err, strlen(err));
    }

    PackageAddBytes(responseTask, (PBYTE)output->buffer, output->length);
    
    LOG("[*] Sending CD response...");
    PParser ResponseParser = sendPackage(responseTask);
    if (ResponseParser) ParserDestroy(ResponseParser);

    PackageDestroy(responseTask);
    PackageDestroy(output);
    LocalFree(taskUuid);

    return TRUE;
}
